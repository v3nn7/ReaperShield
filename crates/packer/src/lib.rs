use reapershield_crypto::{CryptoAlgorithm, EncryptedAsset};
use reapershield_pe_engine::PeEngine;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackerError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Decompression error: {0}")]
    DecompressionError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] reapershield_crypto::CryptoError),

    #[error("PE Engine error: {0}")]
    PeEngineError(#[from] reapershield_pe_engine::PeEngineError),

    #[error("Invalid bundle package format")]
    InvalidPackage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompressionMethod {
    None,
    Lzma,
    Zstd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedFile {
    pub relative_path: String,
    pub original_size: u64,
    pub compressed_size: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedBundle {
    pub compression: CompressionMethod,
    pub is_encrypted: bool,
    pub files: Vec<PackedFile>,
}

pub struct Packer;

impl Packer {
    /// Compresses a buffer using the selected method
    pub fn compress(data: &[u8], method: CompressionMethod) -> Result<Vec<u8>, PackerError> {
        match method {
            CompressionMethod::None => Ok(data.to_vec()),
            CompressionMethod::Zstd => {
                // Default compression level 3 is fast and highly efficient
                zstd::bulk::compress(data, 3)
                    .map_err(|e| PackerError::CompressionError(e.to_string()))
            }
            CompressionMethod::Lzma => {
                let mut input = Cursor::new(data);
                let mut output = Vec::new();
                lzma_rs::lzma_compress(&mut input, &mut output)
                    .map_err(|e| PackerError::CompressionError(e.to_string()))?;
                Ok(output)
            }
        }
    }

    /// Decompresses a buffer using the selected method
    pub fn decompress(data: &[u8], method: CompressionMethod) -> Result<Vec<u8>, PackerError> {
        match method {
            CompressionMethod::None => Ok(data.to_vec()),
            CompressionMethod::Zstd => {
                // Decompress buffer with automatic sizing
                // We don't have to pre-allocate since bulk decompress is versatile
                // But for safety, we can use a maximum expected size or standard decoder
                let mut decoder = zstd::Decoder::new(data)?;
                let mut output = Vec::new();
                decoder.read_to_end(&mut output)?;
                Ok(output)
            }
            CompressionMethod::Lzma => {
                let mut input = Cursor::new(data);
                let mut output = Vec::new();
                lzma_rs::lzma_decompress(&mut input, &mut output)
                    .map_err(|e| PackerError::DecompressionError(e.to_string()))?;
                Ok(output)
            }
        }
    }

    /// Bundles files, compresses them individually or globally, and returns the packed bundle
    pub fn create_bundle<P: AsRef<Path>>(
        files_to_pack: &[(P, String)], // (Absolute Path, Relative path inside archive)
        compression: CompressionMethod,
    ) -> Result<PackedBundle, PackerError> {
        let mut packed_files = Vec::new();

        for (abs_path, rel_path) in files_to_pack {
            let mut file = std::fs::File::open(abs_path)?;
            let size = file.metadata()?.len();
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;

            let compressed_data = Self::compress(&content, compression)?;
            packed_files.push(PackedFile {
                relative_path: rel_path.clone(),
                original_size: size,
                compressed_size: compressed_data.len() as u64,
                data: compressed_data,
            });
        }

        Ok(PackedBundle {
            compression,
            is_encrypted: false,
            files: packed_files,
        })
    }

    /// Encrypts and compresses an entire bundle as a secure standalone payload package
    pub fn encrypt_bundle(
        bundle: &PackedBundle,
        passphrase: &[u8],
        algorithm: CryptoAlgorithm,
    ) -> Result<EncryptedAsset, PackerError> {
        let serialized = serde_json::to_vec(bundle)
            .map_err(|e| PackerError::CompressionError(e.to_string()))?;
        
        let asset = EncryptedAsset::create(&serialized, passphrase, algorithm)?;
        Ok(asset)
    }

    /// Pack an executable: inject a compressed/encrypted payload bundle into the target stub PE
    pub fn pack_binary_assets(
        stub_binary_bytes: &[u8],
        assets_bundle: &PackedBundle,
        passphrase: Option<&[u8]>,
    ) -> Result<Vec<u8>, PackerError> {
        let payload_bytes = if let Some(pass) = passphrase {
            let encrypted = Self::encrypt_bundle(assets_bundle, pass, CryptoAlgorithm::Aes256Gcm)?;
            encrypted.to_bytes()?
        } else {
            serde_json::to_vec(assets_bundle)
                .map_err(|e| PackerError::CompressionError(e.to_string()))?
        };

        // Inject the bundle as a custom PE section called ".reapack" (Reaper Pack)
        // Set characteristics to IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ (0x40000040)
        let modified_pe = PeEngine::inject_section(
            stub_binary_bytes,
            ".reapack",
            &payload_bytes,
            0x4000_0040,
        )?;

        Ok(modified_pe)
    }

    /// Extracts and unpacks the bundle to the target directory path
    pub fn extract_bundle(
        bundle: &PackedBundle,
        target_dir: &Path,
    ) -> Result<(), PackerError> {
        if !target_dir.exists() {
            std::fs::create_dir_all(target_dir)?;
        }

        for file in &bundle.files {
            let decompressed_data = Self::decompress(&file.data, bundle.compression)?;
            let dest_path = target_dir.join(&file.relative_path);

            if let Some(parent) = dest_path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                }
            }

            let mut out_file = std::fs::File::create(&dest_path)?;
            out_file.write_all(&decompressed_data)?;
        }

        Ok(())
    }

    /// Decrypts a secure bundle using the given passphrase and parses it
    pub fn decrypt_bundle(
        encrypted_asset: &EncryptedAsset,
        passphrase: &[u8],
    ) -> Result<PackedBundle, PackerError> {
        let decrypted_bytes = encrypted_asset.decrypt(passphrase)?;
        let bundle: PackedBundle = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| PackerError::CompressionError(e.to_string()))?;
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_compression_decompression() {
        let data = b"This is a sample binary block that has highly redundant words and data structures, repeating again and again!";
        let compressed = Packer::compress(data, CompressionMethod::Zstd).unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = Packer::decompress(&compressed, CompressionMethod::Zstd).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_lzma_compression_decompression() {
        let data = b"This is a test of the LZMA pure rust compression sub-component which can compress and unpack data.";
        let compressed = Packer::compress(data, CompressionMethod::Lzma).unwrap();

        let decompressed = Packer::decompress(&compressed, CompressionMethod::Lzma).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
