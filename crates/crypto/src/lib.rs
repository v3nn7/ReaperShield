use aes_gcm::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Magic header for ReaperShield encrypted assets (`RSEA`).
pub const ASSET_MAGIC: [u8; 4] = *b"RSEA";

/// Current binary asset format version.
pub const ASSET_FORMAT_VERSION: u16 = 2;

/// Recommended PBKDF2 iteration count for 2026 (OWASP guidance, SHA-256: ≥600k).
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid key length (expected 32 bytes)")]
    InvalidKeyLength,

    #[error("Invalid nonce length: got {got}, expected {expected}")]
    InvalidNonceLength { got: usize, expected: usize },

    #[error("Serialization/Deserialization failed: {0}")]
    SerializationError(String),

    #[error("Invalid asset format")]
    InvalidAssetFormat,

    #[error("Unsupported asset format version: {0}")]
    UnsupportedVersion(u16),

    #[error("Bad magic header (corrupted or wrong asset type)")]
    BadMagic,

    #[error("HMAC verification failed")]
    MacMismatch,

    #[error("Key derivation failed: {0}")]
    KdfError(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KdfAlgorithm {
    Pbkdf2Sha256 { iterations: u32 },
    Argon2id { m_cost_kib: u32, t_cost: u32, p_cost: u32 },
}

impl Default for KdfAlgorithm {
    fn default() -> Self {
        KdfAlgorithm::Argon2id {
            m_cost_kib: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Wrapper around a 256-bit key that scrubs memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality check.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(****)")
    }
}

/// Structured payload containing everything required to verify and decrypt resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAsset {
    pub algorithm: CryptoAlgorithm,
    pub kdf: KdfAlgorithm,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
    /// Optional Additional Authenticated Data (context binding, never encrypted).
    #[serde(default)]
    pub aad: Vec<u8>,
    /// Format version of this asset header.
    #[serde(default = "default_version")]
    pub version: u16,
}

fn default_version() -> u16 {
    ASSET_FORMAT_VERSION
}

// -------------------------------------------------------------------------
// Key derivation
// -------------------------------------------------------------------------

/// Derive a strong 256-bit key from a passphrase + salt using PBKDF2-HMAC-SHA256.
pub fn derive_key_pbkdf2(passphrase: &[u8], salt: &[u8], iterations: u32) -> SecretKey {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    SecretKey::new(key)
}

/// Derive a strong 256-bit key from a passphrase + salt using Argon2id.
pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<SecretKey, CryptoError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;
    Ok(SecretKey::new(key))
}

/// Dispatch to the configured KDF.
pub fn derive_key(passphrase: &[u8], salt: &[u8], kdf: KdfAlgorithm) -> Result<SecretKey, CryptoError> {
    match kdf {
        KdfAlgorithm::Pbkdf2Sha256 { iterations } => {
            Ok(derive_key_pbkdf2(passphrase, salt, iterations))
        }
        KdfAlgorithm::Argon2id {
            m_cost_kib,
            t_cost,
            p_cost,
        } => derive_key_argon2id(passphrase, salt, m_cost_kib, t_cost, p_cost),
    }
}

/// Expand a master key into a context-bound subkey using HKDF-SHA256.
pub fn hkdf_expand(master: &SecretKey, info: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .map_err(|e| CryptoError::KdfError(e.to_string()))?;
    Ok(out)
}

// -------------------------------------------------------------------------
// Random generators
// -------------------------------------------------------------------------

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn generate_salt() -> Vec<u8> {
    random_bytes(16)
}

pub fn generate_nonce() -> Vec<u8> {
    random_bytes(12)
}

pub fn generate_xnonce() -> Vec<u8> {
    random_bytes(24)
}

/// Recommend a nonce length for the given algorithm.
pub fn nonce_len_for(alg: CryptoAlgorithm) -> usize {
    match alg {
        CryptoAlgorithm::Aes256Gcm | CryptoAlgorithm::ChaCha20Poly1305 => 12,
        CryptoAlgorithm::XChaCha20Poly1305 => 24,
    }
}

// -------------------------------------------------------------------------
// Raw AEAD wrappers (with AAD support)
// -------------------------------------------------------------------------

pub fn encrypt_aes_gcm(
    data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    encrypt_aes_gcm_aad(data, &[], key, nonce)
}

pub fn decrypt_aes_gcm(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_aes_gcm_aad(encrypted_data, &[], key, nonce)
}

pub fn encrypt_aes_gcm_aad(
    data: &[u8],
    aad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let n = AesNonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: data, aad })
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

pub fn decrypt_aes_gcm_aad(
    encrypted_data: &[u8],
    aad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let n = AesNonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: encrypted_data, aad })
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

pub fn encrypt_chacha20_poly1305(
    data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = ChaChaNonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: data, aad: &[] })
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

pub fn decrypt_chacha20_poly1305(
    encrypted_data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = ChaChaNonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: encrypted_data, aad: &[] })
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

pub fn encrypt_xchacha20_poly1305(
    data: &[u8],
    aad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let n = XNonce::from_slice(nonce);
    cipher
        .encrypt(n, Payload { msg: data, aad })
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

pub fn decrypt_xchacha20_poly1305(
    encrypted_data: &[u8],
    aad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let n = XNonce::from_slice(nonce);
    cipher
        .decrypt(n, Payload { msg: encrypted_data, aad })
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

/// In-place AES-256-GCM encryption (returns appended 16-byte tag).
pub fn encrypt_aes_gcm_in_place(
    buffer: &mut Vec<u8>,
    aad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(), CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let n = AesNonce::from_slice(nonce);
    cipher
        .encrypt_in_place(n, aad, buffer)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

// -------------------------------------------------------------------------
// HMAC / Constant-time helpers
// -------------------------------------------------------------------------

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Verify a 32-byte HMAC tag in constant time.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    if expected.len() != 32 {
        return false;
    }
    let computed = hmac_sha256(key, data);
    bool::from(computed.ct_eq(expected))
}

/// Constant-time slice comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

// -------------------------------------------------------------------------
// EncryptedAsset envelope
// -------------------------------------------------------------------------

impl EncryptedAsset {
    /// Create + encrypt with the default modern KDF (Argon2id).
    pub fn create(
        data: &[u8],
        passphrase: &[u8],
        algorithm: CryptoAlgorithm,
    ) -> Result<Self, CryptoError> {
        Self::create_with(data, passphrase, algorithm, KdfAlgorithm::default(), &[])
    }

    /// Create + encrypt with full control over KDF and AAD.
    pub fn create_with(
        data: &[u8],
        passphrase: &[u8],
        algorithm: CryptoAlgorithm,
        kdf: KdfAlgorithm,
        aad: &[u8],
    ) -> Result<Self, CryptoError> {
        let salt = generate_salt();
        let nonce_len = nonce_len_for(algorithm);
        let nonce = random_bytes(nonce_len);
        let key = derive_key(passphrase, &salt, kdf)?;

        let payload = match algorithm {
            CryptoAlgorithm::Aes256Gcm => {
                let n: &[u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: nonce.len(), expected: 12 })?;
                encrypt_aes_gcm_aad(data, aad, key.as_bytes(), n)?
            }
            CryptoAlgorithm::ChaCha20Poly1305 => {
                let n: &[u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: nonce.len(), expected: 12 })?;
                let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
                let nn = ChaChaNonce::from_slice(n);
                cipher
                    .encrypt(nn, Payload { msg: data, aad })
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?
            }
            CryptoAlgorithm::XChaCha20Poly1305 => {
                let n: &[u8; 24] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: nonce.len(), expected: 24 })?;
                encrypt_xchacha20_poly1305(data, aad, key.as_bytes(), n)?
            }
        };

        Ok(Self {
            algorithm,
            kdf,
            salt,
            nonce,
            payload,
            aad: aad.to_vec(),
            version: ASSET_FORMAT_VERSION,
        })
    }

    /// Decrypt the payload using the provided passphrase.
    pub fn decrypt(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.version > ASSET_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(self.version));
        }
        let key = derive_key(passphrase, &self.salt, self.kdf)?;

        match self.algorithm {
            CryptoAlgorithm::Aes256Gcm => {
                let n: &[u8; 12] = self
                    .nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: self.nonce.len(), expected: 12 })?;
                decrypt_aes_gcm_aad(&self.payload, &self.aad, key.as_bytes(), n)
            }
            CryptoAlgorithm::ChaCha20Poly1305 => {
                let n: &[u8; 12] = self
                    .nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: self.nonce.len(), expected: 12 })?;
                let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
                let nn = ChaChaNonce::from_slice(n);
                cipher
                    .decrypt(nn, Payload { msg: &self.payload, aad: &self.aad })
                    .map_err(|e| CryptoError::DecryptionError(e.to_string()))
            }
            CryptoAlgorithm::XChaCha20Poly1305 => {
                let n: &[u8; 24] = self
                    .nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidNonceLength { got: self.nonce.len(), expected: 24 })?;
                decrypt_xchacha20_poly1305(&self.payload, &self.aad, key.as_bytes(), n)
            }
        }
    }

    pub fn to_json(&self) -> Result<String, CryptoError> {
        serde_json::to_string(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self, CryptoError> {
        serde_json::from_str(json).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Binary format v2:
    /// `RSEA` (4) | version u16 LE | algo u8 | kdf-tag u8 | kdf-params (variable)
    /// | salt_len u32 | salt | nonce_len u32 | nonce | aad_len u32 | aad | payload_len u32 | payload
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = Vec::with_capacity(
            16 + self.salt.len() + self.nonce.len() + self.aad.len() + self.payload.len(),
        );
        bytes.extend_from_slice(&ASSET_MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());

        let algo_byte: u8 = match self.algorithm {
            CryptoAlgorithm::Aes256Gcm => 1,
            CryptoAlgorithm::ChaCha20Poly1305 => 2,
            CryptoAlgorithm::XChaCha20Poly1305 => 3,
        };
        bytes.push(algo_byte);

        // KDF tag + params
        match self.kdf {
            KdfAlgorithm::Pbkdf2Sha256 { iterations } => {
                bytes.push(1);
                bytes.extend_from_slice(&iterations.to_le_bytes());
            }
            KdfAlgorithm::Argon2id { m_cost_kib, t_cost, p_cost } => {
                bytes.push(2);
                bytes.extend_from_slice(&m_cost_kib.to_le_bytes());
                bytes.extend_from_slice(&t_cost.to_le_bytes());
                bytes.extend_from_slice(&p_cost.to_le_bytes());
            }
        }

        write_chunk(&mut bytes, &self.salt);
        write_chunk(&mut bytes, &self.nonce);
        write_chunk(&mut bytes, &self.aad);
        write_chunk(&mut bytes, &self.payload);

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut cur = Cursor::new(bytes);

        let magic = cur.take(4)?;
        if magic != ASSET_MAGIC {
            // Allow loading legacy v1 (no magic): algo u8 then chunks.
            return Self::from_bytes_legacy_v1(bytes);
        }

        let version = u16::from_le_bytes(cur.take(2)?.try_into().unwrap());
        if version > ASSET_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let algo_byte = cur.take(1)?[0];
        let algorithm = match algo_byte {
            1 => CryptoAlgorithm::Aes256Gcm,
            2 => CryptoAlgorithm::ChaCha20Poly1305,
            3 => CryptoAlgorithm::XChaCha20Poly1305,
            _ => return Err(CryptoError::InvalidAssetFormat),
        };

        let kdf_tag = cur.take(1)?[0];
        let kdf = match kdf_tag {
            1 => {
                let iterations = u32::from_le_bytes(cur.take(4)?.try_into().unwrap());
                KdfAlgorithm::Pbkdf2Sha256 { iterations }
            }
            2 => {
                let m_cost_kib = u32::from_le_bytes(cur.take(4)?.try_into().unwrap());
                let t_cost = u32::from_le_bytes(cur.take(4)?.try_into().unwrap());
                let p_cost = u32::from_le_bytes(cur.take(4)?.try_into().unwrap());
                KdfAlgorithm::Argon2id { m_cost_kib, t_cost, p_cost }
            }
            _ => return Err(CryptoError::InvalidAssetFormat),
        };

        let salt = cur.read_chunk()?;
        let nonce = cur.read_chunk()?;
        let aad = cur.read_chunk()?;
        let payload = cur.read_chunk()?;

        Ok(Self {
            algorithm,
            kdf,
            salt,
            nonce,
            payload,
            aad,
            version,
        })
    }

    /// Backwards-compatible loader for the v1 binary layout.
    fn from_bytes_legacy_v1(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 13 {
            return Err(CryptoError::InvalidAssetFormat);
        }
        let mut cur = Cursor::new(bytes);
        let algo_byte = cur.take(1)?[0];
        let algorithm = match algo_byte {
            1 => CryptoAlgorithm::Aes256Gcm,
            2 => CryptoAlgorithm::ChaCha20Poly1305,
            _ => return Err(CryptoError::BadMagic),
        };
        let salt = cur.read_chunk()?;
        let nonce = cur.read_chunk()?;
        let payload = cur.read_chunk()?;
        Ok(Self {
            algorithm,
            kdf: KdfAlgorithm::Pbkdf2Sha256 { iterations: 10_000 },
            salt,
            nonce,
            payload,
            aad: Vec::new(),
            version: 1,
        })
    }
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

fn write_chunk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        if self.pos + n > self.data.len() {
            return Err(CryptoError::InvalidAssetFormat);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn read_chunk(&mut self) -> Result<Vec<u8>, CryptoError> {
        let len_bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CryptoError::InvalidAssetFormat)?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > 256 * 1024 * 1024 {
            // Sanity cap at 256 MiB chunk.
            return Err(CryptoError::InvalidAssetFormat);
        }
        Ok(self.take(len)?.to_vec())
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let original = b"Secret data payload";
        let encrypted = encrypt_aes_gcm(original, &key, &nonce).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key, &nonce).unwrap();
        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_with_aad() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let original = b"important";
        let aad = b"context-binding";
        let enc = encrypt_aes_gcm_aad(original, aad, &key, &nonce).unwrap();
        let dec = decrypt_aes_gcm_aad(&enc, aad, &key, &nonce).unwrap();
        assert_eq!(original, dec.as_slice());
        // Wrong AAD must fail
        assert!(decrypt_aes_gcm_aad(&enc, b"other", &key, &nonce).is_err());
    }

    #[test]
    fn test_chacha_encrypt_decrypt() {
        let key = [9u8; 32];
        let nonce = [4u8; 12];
        let original = b"Some other super secret info";
        let encrypted = encrypt_chacha20_poly1305(original, &key, &nonce).unwrap();
        let decrypted = decrypt_chacha20_poly1305(&encrypted, &key, &nonce).unwrap();
        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_xchacha_encrypt_decrypt() {
        let key = [42u8; 32];
        let nonce = [11u8; 24];
        let original = b"extended-nonce payload";
        let enc = encrypt_xchacha20_poly1305(original, b"meta", &key, &nonce).unwrap();
        let dec = decrypt_xchacha20_poly1305(&enc, b"meta", &key, &nonce).unwrap();
        assert_eq!(original, dec.as_slice());
    }

    #[test]
    fn test_asset_v2_roundtrip_argon2() {
        let original = b"Asset payload";
        let pass = b"correct horse battery staple";
        let asset = EncryptedAsset::create(original, pass, CryptoAlgorithm::XChaCha20Poly1305).unwrap();
        let bytes = asset.to_bytes().unwrap();
        // Sanity: must begin with magic header
        assert_eq!(&bytes[..4], &ASSET_MAGIC);
        let restored = EncryptedAsset::from_bytes(&bytes).unwrap();
        let decrypted = restored.decrypt(pass).unwrap();
        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_asset_v2_roundtrip_pbkdf2() {
        let original = b"Asset payload pbkdf2";
        let pass = b"another secret";
        let asset = EncryptedAsset::create_with(
            original,
            pass,
            CryptoAlgorithm::Aes256Gcm,
            KdfAlgorithm::Pbkdf2Sha256 { iterations: 1_000 },
            b"ctx",
        )
        .unwrap();
        let bytes = asset.to_bytes().unwrap();
        let restored = EncryptedAsset::from_bytes(&bytes).unwrap();
        let decrypted = restored.decrypt(pass).unwrap();
        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let asset = EncryptedAsset::create(b"data", b"good", CryptoAlgorithm::Aes256Gcm).unwrap();
        assert!(asset.decrypt(b"bad").is_err());
    }

    #[test]
    fn test_hkdf_subkey() {
        let master = SecretKey::new([5u8; 32]);
        let a = hkdf_expand(&master, b"context-a", 32).unwrap();
        let b = hkdf_expand(&master, b"context-b", 32).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_hmac_verification() {
        let key = b"secret";
        let data = b"message";
        let mac = hmac_sha256(key, data);
        assert!(verify_hmac(key, data, &mac));
        assert!(!verify_hmac(key, b"tampered", &mac));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_secret_key_ct_eq() {
        let a = SecretKey::new([1u8; 32]);
        let b = SecretKey::new([1u8; 32]);
        let c = SecretKey::new([2u8; 32]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn test_legacy_v1_loader() {
        // Build a fake legacy v1 buffer manually
        let mut buf = Vec::new();
        buf.push(1u8); // AES-GCM
        let salt = vec![0xAAu8; 16];
        buf.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        buf.extend_from_slice(&salt);
        let nonce = vec![0xBBu8; 12];
        buf.extend_from_slice(&(nonce.len() as u32).to_le_bytes());
        buf.extend_from_slice(&nonce);
        let payload = vec![0xCCu8; 5];
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);
        let asset = EncryptedAsset::from_bytes(&buf).unwrap();
        assert_eq!(asset.version, 1);
        assert!(matches!(asset.kdf, KdfAlgorithm::Pbkdf2Sha256 { .. }));
        assert_eq!(asset.salt, salt);
    }
}
