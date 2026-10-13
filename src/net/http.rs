//! Minimal HTTPS/1.1 client (JSON POST/GET).
//! Hand-rolled because the cached environment has no mature HTTP client crate: connect is per-address with a timeout, the body is read exactly per `Content-Length` (chunked fully parsed), so a truncated body is an error rather than a silent partial read.
//! Certificate policy lives in `net::tls` (REST: SPKI TOFU, WSS: no check).

use anyhow::{anyhow, Context, Result};
use rustls::{ClientConnection, StreamOwned};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Read, Write};
use std::path::Path;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub struct HttpsConn {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl HttpsConn {
    pub fn connect(
        host: &str,
        port: u16,
        cfg: Arc<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Result<Self> {
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
            anyhow!("TCP connect to {host}:{port} failed: {}",
                    last_err.map(|e| e.to_string()).unwrap_or_else(|| "no address available".into()))
        })?;
        tcp.set_read_timeout(Some(timeout)).ok();
        tcp.set_write_timeout(Some(timeout)).ok();
        tcp.set_nodelay(true).ok();

        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| anyhow!("invalid SNI: {e}"))?;
        let conn = ClientConnection::new(cfg, server_name)
            .map_err(|e| anyhow!("TLS init failed: {e}"))?;
        Ok(Self { stream: StreamOwned::new(conn, tcp) })
    }

    /// Send a JSON request (default content type `application/json`).
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        self.request_with_type(method, path, host, port, None, body)
    }

    /// Send a request and read the full response body; a `None` content type means `application/json`.
    pub fn request_with_type(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\
             User-Agent: msg-client-rust\r\n"
        );
        if let Some(b) = body {
            req.push_str(&format!("Content-Type: {}\r\n",
                content_type.unwrap_or("application/json")));
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        self.stream.write_all(req.as_bytes()).context("failed to send HTTP request headers")?;
        if let Some(b) = body {
            self.stream.write_all(b).context("failed to send HTTP request body")?;
        }
        self.stream.flush().context("failed to flush HTTP request")?;
        self.read_response()
    }

    fn read_response(&mut self) -> Result<(u16, Vec<u8>)> {
        let mut raw: Vec<u8> = Vec::new();
        let mut head_end: Option<usize> = None;
        let mut status: Option<u16> = None;
        let mut content_len: Option<usize> = None;
        let mut chunked = false;
        let mut buf = [0u8; 8192];

        loop {
            if let Some(he) = head_end {
                if let Some(cl) = content_len {
                    if raw.len().saturating_sub(he + 4) >= cl {
                        break;
                    }
                }
                if chunked && parse_chunked(&raw[he + 4..])?.is_some() {
                    break;
                }
            }
            match self.stream.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if head_end.is_none() {
                        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
                            head_end = Some(pos);
                            let head = String::from_utf8_lossy(&raw[..pos]).to_string();
                            let head_lower = head.to_lowercase();
                            status = head
                                .lines()
                                .next()
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|s| s.parse::<u16>().ok());
                            chunked = head_lower
                                .lines()
                                .any(|l| l.trim_start().starts_with("transfer-encoding:")
                                    && l.to_lowercase().contains("chunked"));
                            content_len = head_lower
                                .lines()
                                .find_map(|l| l.trim_start().strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok());
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    if let Some(he) = head_end {
                        if let Some(cl) = content_len {
                            if raw.len().saturating_sub(he + 4) >= cl {
                                break;
                            }
                        }
                        if chunked && parse_chunked(&raw[he + 4..])?.is_some() {
                            break;
                        }
                    }
                    return Err(anyhow!("timed out reading HTTP response (received {} bytes)", raw.len()));
                }
                Err(e) => return Err(anyhow!("failed to read HTTP response: {e}")),
            }
        }

        if raw.is_empty() {
            return Err(anyhow!("empty response (TLS connection may have been rejected)"));
        }
        let pos = head_end.ok_or_else(|| anyhow!("incomplete response headers (received {} bytes)", raw.len()))?;
        let status = status.ok_or_else(|| anyhow!("cannot parse status line"))?;
        let mut body = raw[pos + 4..].to_vec();

        if let Some(cl) = content_len {
            if body.len() < cl {
                return Err(anyhow!("incomplete response body: Content-Length={cl}, actual {}", body.len()));
            }
            body.truncate(cl);
        } else if chunked {
            body = parse_chunked(&body)?
                .ok_or_else(|| anyhow!("incomplete chunked response body"))?;
        }
        Ok((status, body))
    }

    pub fn request_json(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let bytes = body.map(|v| serde_json::to_vec(v).unwrap());
        let (status, raw) = self.request(method, path, host, port, bytes.as_deref())?;
        let v = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw).unwrap_or_else(|_| {
                Value::String(String::from_utf8_lossy(&raw).to_string())
            })
        };
        Ok((status, v))
    }
}

impl HttpsConn {
    /// Stream a file as the request body (e.g. `application/octet-stream`); the response is read normally.
    pub fn request_upload_file(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        content_type: &str,
        file: &Path,
        file_len: u64,
    ) -> Result<(u16, Vec<u8>)> {
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\
             User-Agent: msg-client-rust\r\nContent-Type: {content_type}\r\n\
             Content-Length: {file_len}\r\n\r\n"
        );
        self.stream.write_all(req.as_bytes()).context("failed to send upload request headers")?;
        let mut f = File::open(file).with_context(|| format!("failed to open upload file: {}", file.display()))?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).context("failed to read upload file")?;
            if n == 0 { break; }
            self.stream.write_all(&buf[..n]).context("failed to send upload data")?;
        }
        self.stream.flush().context("failed to flush upload data")?;
        self.read_response()
    }

    /// Stream the response body to a file.
    ///
    /// With `resume_from > 0` this sends `Range: bytes=<resume_from>-`: a `206` response appends,
    /// but an older server ignoring Range answers `200` with the full body, which must then be
    /// rewritten truncated or the file becomes a stale prefix followed by complete new data.
    ///
    /// Returns `(status, error body)`; on success `(200|206, empty Vec)`, otherwise up to
    /// 64 KiB of the body for the caller to parse.
    pub fn request_download_to_file(
        &mut self,
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        dest: &Path,
        resume_from: u64,
    ) -> Result<(u16, Vec<u8>)> {
        let range_hdr = if resume_from > 0 {
            format!("Range: bytes={resume_from}-\r\n")
        } else {
            String::new()
        };
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\
             User-Agent: msg-client-rust\r\n{range_hdr}\r\n"
        );
        self.stream.write_all(req.as_bytes()).context("failed to send download request")?;
        self.stream.flush().context("failed to flush download request")?;

        // Read the headers, keeping any body bytes already read past them
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 8192];
        let head_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") { break pos; }
            if buf.len() > 64 * 1024 { return Err(anyhow!("response headers too large")); }
            match self.stream.read(&mut tmp) {
                Ok(0) => return Err(anyhow!("incomplete download response headers")),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                    return Err(anyhow!("timed out reading download response headers")),
                Err(e) => return Err(anyhow!("failed to read download response headers: {e}")),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let head_lower = head.to_lowercase();
        let status: u16 = head.lines().next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("cannot parse download status line"))?;
        let content_len: Option<usize> = head_lower.lines()
            .find_map(|l| l.trim_start().strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok());
        let chunked = head_lower.lines().any(|l| l.trim_start()
            .starts_with("transfer-encoding:") && l.to_lowercase().contains("chunked"));
        let mut body = buf[head_end + 4..].to_vec();

        if status != 200 && status != 206 {
            // Error bodies are usually small; keep at most 64 KiB
            loop {
                if body.len() >= 64 * 1024 { break; }
                match self.stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            body.truncate(64 * 1024);
            return Ok((status, body));
        }

        // 206 appends to the existing part; 200 means Range was ignored, so rewrite the file whole
        let append = status == 206;
        let mut f = BufWriter::new(
            if append {
                OpenOptions::new().append(true).open(dest)
                    .with_context(|| format!("failed to append download file: {}", dest.display()))?
            } else {
                File::create(dest)
                    .with_context(|| format!("failed to create download file: {}", dest.display()))?
            });
        if let Some(cl) = content_len {
            if body.len() > cl { body.truncate(cl); }
            f.write_all(&body).context("failed to write download file")?;
            let mut remain = cl.saturating_sub(body.len());
            while remain > 0 {
                match self.stream.read(&mut tmp) {
                    Ok(0) => return Err(anyhow!("incomplete download: {remain} bytes still missing")),
                    Ok(n) => {
                        let take = n.min(remain);
                        f.write_all(&tmp[..take]).context("failed to write download file")?;
                        remain -= take;
                        if take < n { /* extra bytes should not happen: Content-Length is exact */ }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                        return Err(anyhow!("timed out reading download response body ({remain} bytes still missing)")),
                    Err(e) => return Err(anyhow!("failed to read download response body: {e}")),
                }
            }
        } else if chunked {
            stream_chunked(&mut self.stream, body, &mut f)?;
        } else {
            f.write_all(&body).context("failed to write download file")?;
            loop {
                match self.stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => f.write_all(&tmp[..n]).context("failed to write download file")?,
                    Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
                        return Err(anyhow!("timed out reading download response body")),
                    Err(e) => return Err(anyhow!("failed to read download response body: {e}")),
                }
            }
        }
        f.flush().context("failed to flush download file")?;
        Ok((status, Vec::new()))
    }
}

/// Stream-parse a chunked response body into `w`.
fn stream_chunked<R: Read, W: Write>(r: &mut R, mut buf: Vec<u8>, w: &mut W) -> Result<()> {
    let mut tmp = [0u8; 8192];
    loop {
        let nl = loop {
            if let Some(p) = find_subslice(&buf, b"\r\n") { break p; }
            let n = r.read(&mut tmp).context("failed to read chunk")?;
            if n == 0 { return Err(anyhow!("incomplete chunked response")); }
            buf.extend_from_slice(&tmp[..n]);
        };
        let line = String::from_utf8_lossy(&buf[..nl]).to_string();
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("0").trim(), 16)
            .map_err(|e| anyhow!("invalid chunk length: {e}"))?;
        buf.drain(..nl + 2);
        if size == 0 { return Ok(()); }
        while buf.len() < size + 2 {
            let n = r.read(&mut tmp).context("failed to read chunk")?;
            if n == 0 { return Err(anyhow!("incomplete chunked response")); }
            buf.extend_from_slice(&tmp[..n]);
        }
        if &buf[size..size + 2] != b"\r\n" {
            return Err(anyhow!("chunk terminator missing CRLF"));
        }
        w.write_all(&buf[..size]).context("failed to write download file")?;
        buf.drain(..size + 2);
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse a chunked body: `Some(body)` when complete, `None` when more data is needed.
fn parse_chunked(data: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut d = data;
    loop {
        let nl = match find_subslice(d, b"\r\n") {
            Some(p) => p,
            None => return Ok(None),
        };
        let size_line = String::from_utf8_lossy(&d[..nl]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("0").trim(), 16)
            .map_err(|e| anyhow!("invalid chunk length: {e}"))?;
        d = &d[nl + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if d.len() < size + 2 {
            return Ok(None);
        }
        if !d[size..size + 2].eq(b"\r\n") {
            return Err(anyhow!("chunk terminator missing CRLF"));
        }
        out.extend_from_slice(&d[..size]);
        d = &d[size + 2..];
    }
}
