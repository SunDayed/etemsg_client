//! Crypto primitives. Formats and constants are fixed by the existing DB data and the Go relay protocol, so all clients must agree:
//!   · id = sha512(SPKI-DER).hex()[:10]; fingerprint = sha256(SPKI-DER).hex(); digest string = 13 fields joined by "\n"
//!   · text = AES-256-GCM (32B key / 12B iv) with the key wrapped by RSA-4096 OAEP-SHA256; signature = PKCS1v15-SHA256→base64 (challenge signs md5 hex); files use a client-private streaming format

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use md5::Md5;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::signature::Verifier;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

pub const AES_KEY_LEN: usize = 32;
pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// Generate an RSA-4096 keypair; returns (PKCS#1 private PEM, SPKI public PEM), matching Python `generate_rsa_keypair()`.
pub fn generate_keypair() -> Result<(String, String)> {
    let priv_key = RsaPrivateKey::new(&mut OsRng, 4096)
        .context("failed to generate RSA-4096 keypair")?;
    let priv_pem = priv_key
        .to_pkcs1_pem(LineEnding::LF)
        .context("failed to encode private key PEM")?
        .to_string();
    let pub_pem = RsaPublicKey::from(&priv_key)
        .to_public_key_pem(LineEnding::LF)
        .context("failed to encode public key PEM")?;
    Ok((priv_pem, pub_pem))
}

pub fn parse_private(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem.trim()).context("failed to parse private key PEM")
}

pub fn parse_public(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(pem.trim()).context("failed to parse public key PEM")
}

/// SPKI DER (SubjectPublicKeyInfo), matching `cryptography`'s `public_bytes(DER, SubjectPublicKeyInfo)`.
pub fn spki_der(pub_pem: &str) -> Result<Vec<u8>> {
    let key = parse_public(pub_pem)?;
    Ok(key.to_public_key_der().context("failed to encode public key DER")?.as_bytes().to_vec())
}

/// `username = sha512(SPKI-DER).hex()[:10]`
pub fn public_key_id(pub_pem: &str, length: usize) -> Result<String> {
    let der = spki_der(pub_pem)?;
    let digest = Sha512::digest(&der);
    Ok(hex(&digest)[..length.min(128)].to_string())
}

/// SPKI fingerprint of the certificate (matches `tls_pin.spki_sha256_hex`).
pub fn spki_sha256_hex(spki: &[u8]) -> String {
    hex(&Sha256::digest(spki))
}

/// `md5_hex(text)`; challenge login signs the md5 **hex string**, not the raw digest.
pub fn md5_hex(text: &str) -> String {
    hex(&Md5::digest(text.as_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// AES-256-GCM encrypt; returns (ciphertext_b64, iv_b64, tag_b64).
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(String, String, String)> {
    let mut iv = [0u8; GCM_IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init failed: {e}"))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;
    let split = ct.len() - GCM_TAG_LEN;
    Ok((
        B64.encode(&ct[..split]),
        B64.encode(iv),
        B64.encode(&ct[split..]),
    ))
}

pub fn aes_gcm_decrypt(key: &[u8], ct_b64: &str, iv_b64: &str, tag_b64: &str) -> Result<Vec<u8>> {
    let mut buf = B64.decode(ct_b64).context("ciphertext base64 decode failed")?;
    buf.extend_from_slice(&B64.decode(tag_b64).context("tag base64 decode failed")?);
    let iv = B64.decode(iv_b64).context("iv base64 decode failed")?;
    if iv.len() != GCM_IV_LEN {
        return Err(anyhow!("invalid iv length: {}", iv.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init failed: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(&iv), buf.as_ref())
        .map_err(|e| anyhow!("AES-GCM decryption failed: {e}"))
}

/// Encrypt a text message with a random AES-256 key wrapped by RSA-OAEP to the recipient's key; returns (ciphertext_b64, iv_b64, tag_b64, wrapped_key_b64).
pub fn encrypt_text(plain: &str, recipient_pub_pem: &str) -> Result<(String, String, String, String)> {
    let mut key = [0u8; AES_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let (ct, iv, tag) = aes_gcm_encrypt(&key, plain.as_bytes())?;
    let wrapped = rsa_wrap_key(&key, recipient_pub_pem)?;
    Ok((ct, iv, tag, wrapped))
}

/// Decrypt with an already-parsed private key (hot path; avoids re-parsing a 3KB PEM).
pub fn decrypt_text_with_key(
    cipher_b64: &str,
    iv_b64: &str,
    tag_b64: &str,
    wrapped_key_b64: &str,
    priv_key: &RsaPrivateKey,
) -> Result<String> {
    let key = rsa_unwrap_key_with_key(wrapped_key_b64, priv_key)?;
    let pt = aes_gcm_decrypt(&key, cipher_b64, iv_b64, tag_b64)?;
    String::from_utf8(pt).context("plaintext is not valid UTF-8")
}

pub fn rsa_wrap_key(key: &[u8], pub_pem: &str) -> Result<String> {
    let pub_key = parse_public(pub_pem)?;
    let wrapped = pub_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), key)
        .map_err(|e| anyhow!("RSA-OAEP wrap failed: {e}"))?;
    Ok(B64.encode(wrapped))
}

pub fn rsa_unwrap_key_with_key(wrapped_b64: &str, priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let wrapped = B64.decode(wrapped_b64).context("wrapped_key base64 decode failed")?;
    priv_key
        .decrypt(Oaep::new::<Sha256>(), &wrapped)
        .map_err(|e| anyhow!("RSA-OAEP unwrap failed: {e}"))
}

/// Sign with a private key (PKCS1v15-SHA256 → base64); parses the PEM on each call.
pub fn sign_message(priv_pem: &str, fields_str: &str) -> Result<String> {
    let key = parse_private(priv_pem)?;
    sign_message_with_key(&key, fields_str)
}

/// Sign with an already-parsed private key (hot path).
pub fn sign_message_with_key(priv_key: &RsaPrivateKey, data: &str) -> Result<String> {
    let digest = Sha256::digest(data.as_bytes());
    let sig = priv_key
        .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| anyhow!("RSA signing failed: {e}"))?;
    Ok(B64.encode(sig))
}

/// Verify a signature with a public key.
pub fn verify_message_signature(pub_pem: &str, fields_str: &str, sig_b64: &str) -> Result<bool> {
    let verifying = VerifyingKey::<Sha256>::new(parse_public(pub_pem)?);
    let raw = B64.decode(sig_b64).context("signature base64 decode failed")?;
    let sig = RsaSignature::try_from(raw.as_slice()).map_err(|e| anyhow!("malformed signature: {e}"))?;
    Ok(verifying.verify(fields_str.as_bytes(), &sig).is_ok())
}

/// 13-field digest string (the server's `auth.MessageDigest` rebuilds it the same way, joined by "\n"). Receivers must pass the
/// **raw JSON number token** via `build_message_fields_with_ts`: re-parsing to f64 and re-formatting changes low digits, so the rebuilt digest fails at random.
#[allow(clippy::too_many_arguments)]
pub fn build_message_fields(
    msg_id: &str,
    to: &str,
    from_id: &str,
    timestamp: f64,
    msg_type: &str,
    ciphertext: &str,
    iv: &str,
    tag: &str,
    wrapped_key: &str,
    file_id: &str,
    filename: &str,
    size: i64,
    sha256: &str,
) -> String {
    build_message_fields_with_ts(
        msg_id, to, from_id, &fmt_ts(timestamp), msg_type, ciphertext, iv, tag,
        wrapped_key, file_id, filename, size, sha256,
    )
}

/// Like `build_message_fields`, but the timestamp is taken as a string, byte-identical to what the sender signed.
#[allow(clippy::too_many_arguments)]
pub fn build_message_fields_with_ts(
    msg_id: &str,
    to: &str,
    from_id: &str,
    timestamp: &str,
    msg_type: &str,
    ciphertext: &str,
    iv: &str,
    tag: &str,
    wrapped_key: &str,
    file_id: &str,
    filename: &str,
    size: i64,
    sha256: &str,
) -> String {
    [
        msg_id.to_string(),
        to.to_string(),
        from_id.to_string(),
        timestamp.to_string(),
        msg_type.to_string(),
        ciphertext.to_string(),
        iv.to_string(),
        tag.to_string(),
        wrapped_key.to_string(),
        file_id.to_string(),
        filename.to_string(),
        size.to_string(),
        sha256.to_string(),
    ]
    .join("\n")
}

/// Format a timestamp like Go `strconv.FormatFloat(ts,'f',-1,64)` / Python `str(float)`: shortest round-trip, never scientific notation.
pub fn fmt_ts(ts: f64) -> String {
    if ts.fract() == 0.0 {
        // Go's 'f' format prints integral values without ".0", as does Python's str()
        return format!("{}", ts as i64);
    }
    format!("{}", ts)
}

/// Signed REST params with an already-parsed key (hot path); returns (timestamp_ms, nonce_hex, signature_b64) over `[fields..., timestamp, nonce]`.
pub fn build_signed_params_with_key(
    priv_key: &RsaPrivateKey, fields: &[String],
) -> Result<(i64, String, String)> {
    let ts = chrono_now_ms();
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = hex(&nonce_bytes);
    let mut all: Vec<String> = fields.to_vec();
    all.push(ts.to_string());
    all.push(nonce.clone());
    let sig = sign_message_with_key(priv_key, &all.join("\n"))?;
    Ok((ts, nonce, sig))
}

/// Signed REST request body with an already-parsed key (hot path).
pub fn signed_request_body_with_key(
    priv_key: &RsaPrivateKey, fields: &[String],
) -> Result<serde_json::Value> {
    let (ts, nonce, sig) = build_signed_params_with_key(priv_key, fields)?;
    Ok(serde_json::json!({
        "timestamp": ts,
        "nonce": nonce,
        "signature": sig,
    }))
}

// File encryption: client-private streaming format v2 (no interop with the old Python client). The filename is encrypted
// separately (filename_enc); the body is chunked at FILE_CHUNK with derived IVs, AAD = `file_id|size`, ciphertext length == plaintext.
// Per-chunk 16B tags are concatenated in order into message `tag` (covered by the 13-field signature); `iv` carries base_iv, and chunk i uses base_iv's low 32 bits + i (big-endian), so the server cannot reorder or swap chunks; SHA-256 covers the plaintext.

/// File chunk size (ciphertext length == plaintext length).
pub const FILE_CHUNK: usize = 1 << 20;

/// Metadata produced by streaming encryption (no file body).
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub iv_b64: String,
    /// base64 of the per-chunk 16B GCM tags, concatenated in order
    pub tags_b64: String,
    pub wrapped_key_b64: String,
    pub size: u64,
    pub sha256_hex: String,
    /// base64(iv2||ct||tag2) of AES-GCM(key, iv2, filename)
    pub filename_enc_b64: String,
}

/// AAD: `file_id|size` (the plaintext filename is no longer used).
fn file_aad(file_id: &str, size: u64) -> Vec<u8> {
    format!("{file_id}|{size}").into_bytes()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// IV of chunk `idx`: the low 32 bits of base_iv (big-endian) plus idx.
fn derive_chunk_iv(base_iv: &[u8; GCM_IV_LEN], idx: u32) -> [u8; GCM_IV_LEN] {
    let mut iv = *base_iv;
    let ctr = u32::from_be_bytes([base_iv[8], base_iv[9], base_iv[10], base_iv[11]])
        .wrapping_add(idx);
    iv[8..12].copy_from_slice(&ctr.to_be_bytes());
    iv
}

/// Read as much as possible into `buf` (handles short reads); returns the byte count.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("failed to read file"),
        }
    }
    Ok(n)
}

/// `encrypt_filename(key, filename)`; no AAD, output base64(iv||ct||tag).
pub fn encrypt_filename_b64(key: &[u8], filename: &str) -> Result<String> {
    let mut iv = [0u8; GCM_IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init failed: {e}"))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), filename.as_bytes())
        .map_err(|e| anyhow!("filename encryption failed: {e}"))?;
    let mut raw = Vec::with_capacity(GCM_IV_LEN + ct.len());
    raw.extend_from_slice(&iv);
    raw.extend_from_slice(&ct);
    Ok(B64.encode(raw))
}

pub fn decrypt_filename_b64(key: &[u8], enc_b64: &str) -> Result<String> {
    let raw = B64.decode(enc_b64.trim()).context("filename_enc base64 decode failed")?;
    if raw.len() <= GCM_IV_LEN + GCM_TAG_LEN {
        return Err(anyhow!("invalid filename_enc length"));
    }
    let iv = &raw[..GCM_IV_LEN];
    let ct = &raw[GCM_IV_LEN..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("AES init failed: {e}"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(iv), ct)
        .map_err(|e| anyhow!("filename decryption failed: {e}"))?;
    String::from_utf8(pt).context("filename is not valid UTF-8")
}

pub fn decrypt_filename_with_file_key(key: &[u8], enc_b64: &str) -> Result<String> {
    decrypt_filename_b64(key, enc_b64)
}

/// Stream-encrypt `src` into `out` (ciphertext body only; the tag list is in the returned header).
pub fn encrypt_file_streaming(
    src: &Path, filename: &str, file_id: &str, recipient_pub_pem: &str, out: &Path,
) -> Result<FileHeader> {
    let size = std::fs::metadata(src)
        .with_context(|| format!("failed to stat file: {}", src.display()))?
        .len();
    let mut key = [0u8; AES_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let mut base_iv = [0u8; GCM_IV_LEN];
    OsRng.fill_bytes(&mut base_iv);
    let wrapped = rsa_wrap_key(&key, recipient_pub_pem)?;
    let filename_enc = encrypt_filename_b64(&key, filename)?;
    let aad = file_aad(file_id, size);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES init failed: {e}"))?;

    let mut fin = BufReader::new(
        File::open(src).with_context(|| format!("failed to open file: {}", src.display()))?);
    let mut fout = BufWriter::new(
        File::create(out).with_context(|| format!("failed to create temp file: {}", out.display()))?);
    let mut sha = Sha256::new();
    let mut tags: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; FILE_CHUNK];
    let mut idx: u32 = 0;
    loop {
        let n = read_full(&mut fin, &mut buf)?;
        if n == 0 { break; }
        let plain = &buf[..n];
        sha.update(plain);
        let iv = derive_chunk_iv(&base_iv, idx);
        let ct = cipher
            .encrypt(Nonce::from_slice(&iv), Payload { msg: plain, aad: &aad })
            .map_err(|e| anyhow!("file encryption failed: {e}"))?;
        let split = ct.len() - GCM_TAG_LEN;
        fout.write_all(&ct[..split]).context("failed to write ciphertext")?;
        tags.extend_from_slice(&ct[split..]);
        idx = idx.checked_add(1).context("too many file chunks")?;
    }
    fout.flush().context("failed to flush ciphertext")?;
    Ok(FileHeader {
        iv_b64: B64.encode(base_iv),
        tags_b64: B64.encode(tags),
        wrapped_key_b64: wrapped,
        size,
        sha256_hex: hex(&sha.finalize()),
        filename_enc_b64: filename_enc,
    })
}

/// Stream-decrypt `src` (raw ciphertext) into `dest` and verify SHA-256; prefer a temporary `dest` renamed on success.
pub fn decrypt_file_streaming(
    src: &Path,
    dest: &Path,
    priv_key: &RsaPrivateKey,
    file_id: &str,
    size: u64,
    iv_b64: &str,
    tags_b64: &str,
    wrapped_key_b64: &str,
    expected_sha256: &str,
) -> Result<()> {
    let key = rsa_unwrap_key_with_key(wrapped_key_b64, priv_key)?;
    let base_vec = B64.decode(iv_b64.trim()).context("file iv decode failed")?;
    if base_vec.len() != GCM_IV_LEN {
        return Err(anyhow!("invalid file iv length: {}", base_vec.len()));
    }
    let mut base_iv = [0u8; GCM_IV_LEN];
    base_iv.copy_from_slice(&base_vec);
    let tags = B64.decode(tags_b64.trim()).context("file tag decode failed")?;
    let nchunks = if size == 0 { 0usize }
        else { ((size + FILE_CHUNK as u64 - 1) / FILE_CHUNK as u64) as usize };
    if tags.len() != nchunks * GCM_TAG_LEN {
        return Err(anyhow!("file tag count mismatch: expected {nchunks}, actual {}",
                           tags.len() / GCM_TAG_LEN));
    }
    let aad = file_aad(file_id, size);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES init failed: {e}"))?;

    let mut fin = BufReader::new(
        File::open(src).with_context(|| format!("failed to open ciphertext: {}", src.display()))?);
    let mut fout = BufWriter::new(
        File::create(dest).with_context(|| format!("failed to create plaintext file: {}", dest.display()))?);
    let mut sha = Sha256::new();
    let mut remaining = size;
    let mut idx = 0usize;
    let mut buf = vec![0u8; FILE_CHUNK];
    while remaining > 0 {
        let want = std::cmp::min(remaining, FILE_CHUNK as u64) as usize;
        let got = read_full(&mut fin, &mut buf[..want])?;
        if got != want {
            anyhow::bail!("incomplete ciphertext: expected {want} bytes, actual {got}");
        }
        let mut ct = Vec::with_capacity(want + GCM_TAG_LEN);
        ct.extend_from_slice(&buf[..want]);
        ct.extend_from_slice(&tags[idx * GCM_TAG_LEN..(idx + 1) * GCM_TAG_LEN]);
        let iv = derive_chunk_iv(&base_iv, idx as u32);
        let pt = cipher
            .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: &aad })
            .map_err(|e| anyhow!("file chunk decryption failed(#{idx}): {e}"))?;
        if pt.len() != want {
            anyhow::bail!("file chunk has an unexpected length");
        }
        sha.update(&pt);
        fout.write_all(&pt).context("failed to write plaintext")?;
        remaining -= want as u64;
        idx += 1;
    }
    fout.flush().context("failed to flush plaintext")?;
    let actual = hex(&sha.finalize());
    if actual != expected_sha256 {
        anyhow::bail!("file verification failed (SHA-256 mismatch)");
    }
    Ok(())
}

pub fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn generate_msg_id() -> String {
    uuid_like()
}

/// Random ID shaped like Python's `str(uuid.uuid4())`.
fn uuid_like() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]
    )
}

#[cfg(test)]
mod file_crypto_tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mcrt_test_{}_{}", std::process::id(), name))
    }

    #[test]
    fn filename_roundtrip() {
        let key = [7u8; 32];
        let enc = encrypt_filename_b64(&key, "test file(1).bin").unwrap();
        assert_eq!(decrypt_filename_b64(&key, &enc).unwrap(), "test file(1).bin");
    }

    fn roundtrip(priv_key: &RsaPrivateKey, pub_pem: &str, size: usize) {
        let plain: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let src = tmp(&format!("src_{size}.bin"));
        let enc = tmp(&format!("enc_{size}.bin"));
        let dec = tmp(&format!("dec_{size}.bin"));
        std::fs::write(&src, &plain).unwrap();
        let file_id = "test-file-id";
        let h = encrypt_file_streaming(&src, "a.txt", file_id, pub_pem, &enc).unwrap();
        assert_eq!(h.size, size as u64);
        // ciphertext length == plaintext length (matches the server's `size` semantics)
        assert_eq!(std::fs::metadata(&enc).unwrap().len(), size as u64);
        let fkey = rsa_unwrap_key_with_key(&h.wrapped_key_b64, priv_key).unwrap();
        assert_eq!(decrypt_filename_b64(&fkey, &h.filename_enc_b64).unwrap(), "a.txt");
        decrypt_file_streaming(&enc, &dec, priv_key, file_id, h.size,
            &h.iv_b64, &h.tags_b64, &h.wrapped_key_b64, &h.sha256_hex).unwrap();
        assert_eq!(std::fs::read(&dec).unwrap(), plain);

        // AAD binds file_id: any other file_id must fail to decrypt (empty files have no chunk to bind AAD to, so skip)
        if size > 0 {
            let bad = tmp(&format!("bad_{size}.bin"));
            assert!(decrypt_file_streaming(&enc, &bad, priv_key, "other-file-id", h.size,
                &h.iv_b64, &h.tags_b64, &h.wrapped_key_b64, &h.sha256_hex).is_err());
            let _ = std::fs::remove_file(bad);
        }
        for p in [src, enc, dec] { let _ = std::fs::remove_file(p); }
    }

    #[test]
    fn file_roundtrip_various_sizes() {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_pem = RsaPublicKey::from(&priv_key)
            .to_public_key_pem(LineEnding::LF).unwrap();
        for size in [0usize, 1, 1000, FILE_CHUNK, FILE_CHUNK + 1, FILE_CHUNK * 2 + 123] {
            roundtrip(&priv_key, &pub_pem, size);
        }
    }
}


#[cfg(test)]
mod wire_signature_tests {
    use super::*;
    use rsa::pkcs8::EncodePublicKey;

    fn keypair() -> (RsaPrivateKey, String) {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_pem = RsaPublicKey::from(&priv_key).to_public_key_pem(LineEnding::LF).unwrap();
        (priv_key, pub_pem)
    }

    /// Regression: `serde_json` re-formatting f64 is **lossy** (~12% of values), so digests rebuilt from `as_f64()` stop matching the sender's and messages used to be dropped at random.
    #[test]
    fn json_f64_roundtrip_is_lossy_hence_token_required() {
        let mut changed = 0;
        for _ in 0..500 {
            let ts = now_secs();
            let signed = fmt_ts(ts);
            let v = serde_json::json!({ "timestamp": ts });
            let wire = v.to_string();
            let back: serde_json::Value = serde_json::from_str(&wire).unwrap();
            let rebuilt = fmt_ts(back.get("timestamp").and_then(|x| x.as_f64()).unwrap_or(0.0));
            if rebuilt != signed { changed += 1; }
        }
        assert!(changed > 0,
            "expected serde_json's f64 round-trip to change some values (about 12% measured), actual 0/500");
    }

    /// The fix: rebuild the digest from the raw JSON token; 200 back-to-back messages all verify.
    #[test]
    fn rapid_messages_verify_via_raw_token() {
        let (priv_key, pub_pem) = keypair();
        let me = "a5112fd8ec";
        let peer = "801ec47b5c";
        for i in 0..200 {
            // sender (as in core.rs::send_text)
            let (ct, iv, tag, wrapped) = encrypt_text(&format!("msg {i}"), &pub_pem).unwrap();
            let msg_id = generate_msg_id();
            let ts = now_secs();
            let signed = build_message_fields(
                &msg_id, peer, me, ts, "", &ct, &iv, &tag, &wrapped, "", "", 0, "");
            let sig = sign_message_with_key(&priv_key, &signed).unwrap();

            let payload = serde_json::json!({
                "from": me, "to": peer, "ciphertext": ct, "iv": iv, "tag": tag,
                "msg_id": msg_id, "timestamp": ts, "wrapped_key": wrapped, "signature": sig
            });
            let wire = payload.to_string();
            let got: serde_json::Value = serde_json::from_str(&wire).unwrap();

            // receiver: rebuild from the raw token only (as in core.rs::store_incoming)
            let token = crate::store::extract_timestamp_token(&wire)
                .expect("must extract the timestamp token from the wire text");
            let g = |k: &str| got.get(k).and_then(|v| v.as_str()).unwrap_or("");
            let rebuilt = build_message_fields_with_ts(
                g("msg_id"), peer, me, &token,
                g("msg_type"), g("ciphertext"), g("iv"), g("tag"),
                g("wrapped_key"), g("file_id"), g("filename"),
                got.get("size").and_then(|v| v.as_i64()).unwrap_or(0), g("sha256"));

            assert_eq!(rebuilt, signed, "message {i} digest string mismatch");
            assert!(verify_message_signature(&pub_pem, &rebuilt, g("signature")).unwrap(),
                "message {i} signature verification failed");
        }
    }

    /// Offline messages must be sliced byte-wise from the **raw response text**: `Value::to_string()` re-formats f64 timestamps and changes low digits; this checks the slice preserves the exact decimal literal.
    #[test]
    fn raw_array_slice_preserves_timestamp_token() {
        let (priv_key, pub_pem) = keypair();
        let me = "a5112fd8ec";
        let peer = "801ec47b5c";
        let mut via_value_differs = 0;

        for i in 0..200 {
            let (ct, iv, tag, wrapped) = encrypt_text(&format!("offline {i}"), &pub_pem).unwrap();
            let msg_id = generate_msg_id();
            let ts = now_secs();
            let token = fmt_ts(ts);
            let signed = build_message_fields_with_ts(
                &msg_id, peer, me, &token, "", &ct, &iv, &tag, &wrapped, "", "", 0, "");
            let sig = sign_message_with_key(&priv_key, &signed).unwrap();

            // simulate the server body (the timestamp is written as the raw token)
            let body = format!(
                r#"{{"status":"ok","payload":{{"messages":[
                   {{"from":"{me}","msg_id":"{msg_id}","timestamp":{token},
                    "ciphertext":"{ct}","iv":"{iv}","tag":"{tag}",
                    "wrapped_key":"{wrapped}","signature":"{sig}"}}]}}}}"#);

            let objs = crate::store::extract_json_array_objects(&body, "messages");
            assert_eq!(objs.len(), 1, "should slice out exactly 1 element");
            let got_token = crate::store::extract_timestamp_token(&objs[0]).unwrap();
            assert_eq!(got_token, token, "the raw slice must preserve the timestamp token byte for byte");

            let m: serde_json::Value = serde_json::from_str(&objs[0]).unwrap();
            let g = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("");
            let rebuilt = build_message_fields_with_ts(
                g("msg_id"), peer, me, &got_token, "", g("ciphertext"), g("iv"), g("tag"),
                g("wrapped_key"), "", "", 0, "");
            assert!(verify_message_signature(&pub_pem, &rebuilt, g("signature")).unwrap(),
                "offline message {i} signature verification failed");

            let via_value = m.to_string();
            if crate::store::extract_timestamp_token(&via_value).as_deref() != Some(token.as_str()) {
                via_value_differs += 1;
            }
        }
        assert!(via_value_differs > 0,
            "expected Value::to_string() to change the low digit of some timestamps, actual 0/200");
    }
}

#[cfg(test)]
mod timestamp_token_tests {
    use crate::store::extract_timestamp_token;

    #[test]
    fn extracts_plain_number() {
        let s = r#"{"from":"a","timestamp":1790603481.2200553,"signature":"x"}"#;
        assert_eq!(extract_timestamp_token(s).as_deref(), Some("1790603481.2200553"));
    }

    #[test]
    fn handles_integer_and_exponent() {
        assert_eq!(extract_timestamp_token(r#"{"timestamp":1790603481}"#).as_deref(),
                   Some("1790603481"));
        assert_eq!(extract_timestamp_token(r#"{"timestamp":1.5e3}"#).as_deref(), Some("1.5e3"));
        assert_eq!(extract_timestamp_token(r#"{"timestamp": -12.5}"#).as_deref(), Some("-12.5"));
    }

    /// A `"timestamp"` appearing inside a message body must not be mistaken for the key.
    #[test]
    fn ignores_timestamp_inside_string_values() {
        let s = r#"{"text":"say \"timestamp\": 999","timestamp":42}"#;
        assert_eq!(extract_timestamp_token(s).as_deref(), Some("42"));
    }

    #[test]
    fn returns_none_when_absent_or_malformed() {
        assert_eq!(extract_timestamp_token(r#"{"from":"a"}"#), None);
        assert_eq!(extract_timestamp_token(r#"{"timestamp":"not-a-number"}"#), None);
        assert_eq!(extract_timestamp_token(""), None);
    }
}
