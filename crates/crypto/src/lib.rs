use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid key length (expected 32 bytes)")]
    InvalidKeyLength,

    #[error("Serialization/Deserialization failed: {0}")]
    SerializationError(String),

    #[error("Invalid asset format")]
    InvalidAssetFormat,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Structured payload containing everything required to verify and decrypt resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAsset {
    pub algorithm: CryptoAlgorithm,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Derives a strong 256-bit key from a passphrase/pin and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    key
}

/// Generates a cryptographically secure random 16-byte salt.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random 12-byte nonce/IV.
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts raw binary data with AES-256-GCM.
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let aes_nonce = AesNonce::from_slice(nonce);
    cipher
        .encrypt(aes_nonce, data)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

/// Decrypts raw binary data with AES-256-GCM.
pub fn decrypt_aes_gcm(encrypted_data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let aes_nonce = AesNonce::from_slice(nonce);
    cipher
        .decrypt(aes_nonce, encrypted_data)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

/// Encrypts raw binary data with ChaCha20-Poly1305.
pub fn encrypt_chacha20_poly1305(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let chacha_nonce = ChaChaNonce::from_slice(nonce);
    cipher
        .encrypt(chacha_nonce, data)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))
}

/// Decrypts raw binary data with ChaCha20-Poly1305.
pub fn decrypt_chacha20_poly1305(encrypted_data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let chacha_nonce = ChaChaNonce::from_slice(nonce);
    cipher
        .decrypt(chacha_nonce, encrypted_data)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

impl EncryptedAsset {
    /// Creates and encrypts a new resource asset using the specified algorithm and key.
    pub fn create(
        data: &[u8],
        passphrase: &[u8],
        algorithm: CryptoAlgorithm,
    ) -> Result<Self, CryptoError> {
        let salt = generate_salt();
        let nonce = generate_nonce();
        let key = derive_key(passphrase, &salt, 10_000);

        let payload = match algorithm {
            CryptoAlgorithm::Aes256Gcm => {
                let nonce_arr: &[u8; 12] = nonce.as_slice().try_into().map_err(|_| CryptoError::InvalidAssetFormat)?;
                encrypt_aes_gcm(data, &key, nonce_arr)?
            }
            CryptoAlgorithm::ChaCha20Poly1305 => {
                let nonce_arr: &[u8; 12] = nonce.as_slice().try_into().map_err(|_| CryptoError::InvalidAssetFormat)?;
                encrypt_chacha20_poly1305(data, &key, nonce_arr)?
            }
        };

        Ok(Self {
            algorithm,
            salt,
            nonce,
            payload,
        })
    }

    /// Decrypts the payload of the asset using the provided passphrase.
    pub fn decrypt(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = derive_key(passphrase, &self.salt, 10_000);
        let nonce_arr: &[u8; 12] = self.nonce.as_slice().try_into().map_err(|_| CryptoError::InvalidAssetFormat)?;

        match self.algorithm {
            CryptoAlgorithm::Aes256Gcm => decrypt_aes_gcm(&self.payload, &key, nonce_arr),
            CryptoAlgorithm::ChaCha20Poly1305 => decrypt_chacha20_poly1305(&self.payload, &key, nonce_arr),
        }
    }

    /// Serializes the asset to a JSON string.
    pub fn to_json(&self) -> Result<String, CryptoError> {
        serde_json::to_string(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Deserializes the asset from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, CryptoError> {
        serde_json::from_str(json).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Serializes the asset to binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        // Simple and robust binary format:
        // [1 byte algorithm] [4 bytes salt_len] [salt] [4 bytes nonce_len] [nonce] [4 bytes payload_len] [payload]
        let mut bytes = Vec::new();
        
        let algo_byte = match self.algorithm {
            CryptoAlgorithm::Aes256Gcm => 1u8,
            CryptoAlgorithm::ChaCha20Poly1305 => 2u8,
        };
        bytes.push(algo_byte);

        bytes.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.salt);

        bytes.extend_from_slice(&(self.nonce.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);

        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);

        Ok(bytes)
    }

    /// Deserializes the asset from binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 13 {
            return Err(CryptoError::InvalidAssetFormat);
        }

        let algo_byte = bytes[0];
        let algorithm = match algo_byte {
            1 => CryptoAlgorithm::Aes256Gcm,
            2 => CryptoAlgorithm::ChaCha20Poly1305,
            _ => return Err(CryptoError::InvalidAssetFormat),
        };

        let mut offset = 1;

        if offset + 4 > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let salt_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + salt_len > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let salt = bytes[offset..offset+salt_len].to_vec();
        offset += salt_len;

        if offset + 4 > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let nonce_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + nonce_len > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let nonce = bytes[offset..offset+nonce_len].to_vec();
        offset += nonce_len;

        if offset + 4 > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let payload_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + payload_len > bytes.len() { return Err(CryptoError::InvalidAssetFormat); }
        let payload = bytes[offset..offset+payload_len].to_vec();

        Ok(Self {
            algorithm,
            salt,
            nonce,
            payload,
        })
    }
}

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
    fn test_chacha_encrypt_decrypt() {
        let key = [9u8; 32];
        let nonce = [4u8; 12];
        let original = b"Some other super secret info";

        let encrypted = encrypt_chacha20_poly1305(original, &key, &nonce).unwrap();
        let decrypted = decrypt_chacha20_poly1305(&encrypted, &key, &nonce).unwrap();

        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_asset_serialization() {
        let original = b"Asset payload compression secure data";
        let pass = b"secure_password_123";

        let asset = EncryptedAsset::create(original, pass, CryptoAlgorithm::ChaCha20Poly1305).unwrap();
        let bytes = asset.to_bytes().unwrap();

        let restored = EncryptedAsset::from_bytes(&bytes).unwrap();
        let decrypted = restored.decrypt(pass).unwrap();

        assert_eq!(original, decrypted.as_slice());
    }
}
