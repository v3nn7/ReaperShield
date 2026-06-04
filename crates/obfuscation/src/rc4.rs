//! RC4 stream cipher for string / blob obfuscation.
//!
//! RC4 is broken for confidentiality at scale, but for obfuscating in-binary
//! strings against trivial static analysis it provides materially better
//! entropy than single-byte XOR while remaining tiny (~30 bytes of decoder
//! logic) and key-agile.

use rand::Rng;

/// Streaming RC4 cipher state.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Build a new RC4 state from `key`. Panics if key is empty.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        let mut s = [0u8; 256];
        for (idx, b) in s.iter_mut().enumerate() {
            *b = idx as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Process `data` in-place (encryption / decryption are symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let t = (self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize;
            *byte ^= self.s[t];
        }
    }

    /// Convenience wrapper: returns the encrypted copy of `data`.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.apply(&mut out);
        out
    }

    /// Convenience wrapper: returns the decrypted copy of `data`.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

/// Encrypt `data` with RC4 using `key`. Returns a new vector.
pub fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    Rc4::new(key).apply(&mut out);
    out
}

/// Generate a fresh pseudo-random RC4 key of `len` bytes.
pub fn random_key(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Multi-byte rotating XOR (lighter than RC4, stronger than single-byte XOR).
pub fn rotating_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()].wrapping_add((i as u8).wrapping_mul(0x1B)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_roundtrip() {
        let key = b"k3y!";
        let plaintext = b"The quick brown fox";
        let ct = rc4_encrypt(key, plaintext);
        assert_ne!(plaintext.as_slice(), ct.as_slice());
        let pt = rc4_encrypt(key, &ct);
        assert_eq!(plaintext.as_slice(), pt.as_slice());
    }

    #[test]
    fn rc4_test_vector() {
        // Classic Wikipedia vector: Key "Key", PT "Plaintext" -> BBF316E8D940AF0AD3
        let ct = rc4_encrypt(b"Key", b"Plaintext");
        assert_eq!(
            ct,
            vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
    }

    #[test]
    fn rotating_xor_roundtrip_diff_to_plain_xor() {
        let key = b"abc";
        let data = b"deadbeefcafebabe";
        let enc = rotating_xor(data, key);
        assert_ne!(enc, data);
        // Decrypt by recomputing the same stream (key derivation depends on i).
        let dec_mask: Vec<u8> = (0..data.len())
            .map(|i| key[i % key.len()].wrapping_add((i as u8).wrapping_mul(0x1B)))
            .collect();
        let decrypted: Vec<u8> = enc.iter().zip(dec_mask.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn random_key_length() {
        assert_eq!(random_key(16).len(), 16);
        assert_eq!(random_key(32).len(), 32);
    }
}
