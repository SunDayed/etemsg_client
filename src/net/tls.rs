//! TLS: rustls custom verifier with SPKI SHA-256 fingerprint pinning (TOFU); no CA-chain validation because the server uses a self-signed certificate.
//! A mismatch against the fingerprint recorded on the first connect means a man-in-the-middle and aborts the handshake.
//! `pin_check = None` accepts any certificate, leaving connection security entirely to application-layer encryption/signing (only REST pins; WSS does not).

use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::fmt;
use std::sync::Arc;

/// Pin callback: receives the SPKI SHA-256 hex; returning `Err` aborts the handshake.
pub type PinCheck = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct PinningVerifier {
    pin_check: Option<PinCheck>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinningVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinningVerifier")
    }
}

impl PinningVerifier {
    pub fn new(pin_check: Option<PinCheck>) -> Self {
        Self { pin_check, algorithms: ring::default_provider().signature_verification_algorithms }
    }

    /// Extract the raw SPKI DER from a certificate and hash it with SHA-256.
    pub fn spki_sha256_from_cert(der: &[u8]) -> Result<String> {
        use x509_parser::prelude::*;
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| anyhow!("X.509 parse failed: {e}"))?;
        let spki_raw = cert.tbs_certificate.subject_pki.raw;
        Ok(crate::crypto::spki_sha256_hex(spki_raw))
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let pin = Self::spki_sha256_from_cert(end_entity.as_ref())
            .map_err(|e| TlsError::General(e.to_string()))?;
        if let Some(cb) = &self.pin_check {
            cb(&pin).map_err(TlsError::General)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

pub fn client_config(pin_check: Option<PinCheck>) -> Arc<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS protocol version")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinningVerifier::new(pin_check)))
            .with_no_client_auth(),
    )
}
