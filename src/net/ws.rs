//! WebSocket client over a custom rustls stream; tungstenite (RFC 6455) handles the handshake, framing, fragmentation, ping/pong and close.
//! Frame and message sizes are capped so a hostile peer cannot balloon memory; connect and handshake are timeout-bounded, and the short post-handshake read timeout lets one thread both send and keep heartbeats going.
//! No server certificate validation (`client_config(None)`): security rests on application-layer RSA encryption/signing, REST additionally checks SPKI TOFU. `presence`/`group_notify` pushes are handled without I/O and group sync is deferred to the caller's background worker — blocking this receive thread would stall heartbeats.

use anyhow::{anyhow, Context, Result};
use rustls::{ClientConnection, StreamOwned};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::error::Error as WsError;
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};

#[derive(Debug, Clone)]
pub enum WsFrame {
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
    Binary(Vec<u8>),
}

type WsStream = StreamOwned<ClientConnection, TcpStream>;

pub struct WsClient {
    ws: WebSocket<WsStream>,
}

impl WsClient {
    pub fn connect(
        host: &str,
        port: u16,
        path: &str,
        cfg: Arc<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Result<Self> {
        // Try every resolved address with a timeout: a bare `TcpStream::connect` can block forever
        let addrs = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("failed to resolve {host}:{port}"))?;
        let mut tcp = None;
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(s) => { tcp = Some(s); break; }
                Err(e) => last_err = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            anyhow!("WS TCP connect to {host}:{port} failed: {}",
                    last_err.map(|e| e.to_string()).unwrap_or_else(|| "no address available".into()))
        })?;
        tcp.set_read_timeout(Some(timeout)).ok();
        tcp.set_write_timeout(Some(timeout)).ok();
        tcp.set_nodelay(true).ok();

        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("invalid SNI: {e}"))?;
        let conn = ClientConnection::new(cfg, server_name)
            .map_err(|e| anyhow!("WS TLS init failed: {e}"))?;
        let stream = StreamOwned::new(conn, tcp);

        let url = format!("wss://{host}:{port}{path}");
        let config = WebSocketConfig::default()
            .max_message_size(Some(8 << 20))   // 8 MiB per message
            .max_frame_size(Some(1 << 20))     // 1 MiB per frame
            .write_buffer_size(0);             // write through, no buffering
        let (ws, _resp) = tungstenite::client::client_with_config(&url, stream, Some(config))
            .map_err(|e| match e {
                tungstenite::handshake::HandshakeError::Failure(f) => anyhow!("WS handshake failed: {f}"),
                tungstenite::handshake::HandshakeError::Interrupted(_) =>
                    anyhow!("WS handshake timed out (not completed within {timeout:?})"),
            })?;

        // After the handshake use a short polling read timeout so one thread can both send and receive
        if let Err(e) = ws.get_ref().sock.set_read_timeout(Some(Duration::from_millis(200))) {
            return Err(anyhow!("failed to set WS read timeout: {e}"));
        }
        Ok(Self { ws })
    }

    pub fn send_text(&mut self, s: &str) -> Result<()> {
        self.ws.send(Message::text(s)).map_err(|e| anyhow!("WS send failed: {e}"))
    }

    /// Send a close frame; does not wait for the peer (read/drop completes the close).
    pub fn send_close(&mut self) -> Result<()> {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
        Ok(())
    }

    /// Read one whole message; a socket read timeout returns `Ok(None)` (tungstenite keeps partial-frame state).
    pub fn read_frame(&mut self) -> Result<Option<WsFrame>> {
        match self.ws.read() {
            Ok(Message::Text(t)) => Ok(Some(WsFrame::Text(t.as_str().to_string()))),
            Ok(Message::Binary(b)) => Ok(Some(WsFrame::Binary(b.to_vec()))),
            Ok(Message::Ping(p)) => Ok(Some(WsFrame::Ping(p.to_vec()))),
            Ok(Message::Pong(p)) => Ok(Some(WsFrame::Pong(p.to_vec()))),
            Ok(Message::Close(_)) => Ok(Some(WsFrame::Close)),
            Ok(Message::Frame(_)) => Ok(None),
            Err(WsError::ConnectionClosed) | Err(WsError::AlreadyClosed) => {
                Ok(Some(WsFrame::Close))
            }
            Err(WsError::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(anyhow!("WS read failed: {e}")),
        }
    }
}
