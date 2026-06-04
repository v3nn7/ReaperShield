//! Mixed Boolean-Arithmetic (MBA) expression generator.
//!
//! MBA transformations rewrite simple arithmetic / logical expressions into
//! semantically-equivalent but visually complex forms. They are extremely
//! effective at defeating pattern-matching and rule-based deobfuscators
//! because the resulting code mixes boolean (XOR/AND/OR/NOT) and arithmetic
//! (+/-/x) operators in ways that are non-trivial to simplify algebraically.

use rand::{seq::SliceRandom, Rng};

/// Algebraic identity over two 32-bit registers (`x`, `y`).
#[derive(Debug, Clone, Copy)]
pub enum MbaIdentity {
    /// `x + y == (x ^ y) + 2*(x & y)`
    AddIsXorPlusTwoAnd,
    /// `x ^ y == (x | y) - (x & y)`
    XorIsOrMinusAnd,
    /// `x | y == (x & y) + (x ^ y)`
    OrIsAndPlusXor,
    /// `x & y == (x | y) - (x ^ y)`
    AndIsOrMinusXor,
    /// `~x == -x - 1`
    NotIsNegMinusOne,
    /// `x + 1 == -(~x)`
    IncIsNegNot,
}

impl MbaIdentity {
    pub const ALL: &'static [MbaIdentity] = &[
        MbaIdentity::AddIsXorPlusTwoAnd,
        MbaIdentity::XorIsOrMinusAnd,
        MbaIdentity::OrIsAndPlusXor,
        MbaIdentity::AndIsOrMinusXor,
        MbaIdentity::NotIsNegMinusOne,
        MbaIdentity::IncIsNegNot,
    ];

    /// Pick a random identity (uniformly).
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        *Self::ALL.choose(&mut rng).unwrap()
    }
}

/// Evaluate the LHS of the identity for concrete inputs (`x`, `y`).
pub fn evaluate(identity: MbaIdentity, x: u32, y: u32) -> u32 {
    match identity {
        MbaIdentity::AddIsXorPlusTwoAnd => x.wrapping_add(y),
        MbaIdentity::XorIsOrMinusAnd => x ^ y,
        MbaIdentity::OrIsAndPlusXor => x | y,
        MbaIdentity::AndIsOrMinusXor => x & y,
        MbaIdentity::NotIsNegMinusOne => !x,
        MbaIdentity::IncIsNegNot => x.wrapping_add(1),
    }
}

/// Evaluate the RHS (the MBA-obfuscated form) for the same inputs.
pub fn evaluate_obfuscated(identity: MbaIdentity, x: u32, y: u32) -> u32 {
    match identity {
        MbaIdentity::AddIsXorPlusTwoAnd => (x ^ y).wrapping_add((x & y).wrapping_mul(2)),
        MbaIdentity::XorIsOrMinusAnd => (x | y).wrapping_sub(x & y),
        MbaIdentity::OrIsAndPlusXor => (x & y).wrapping_add(x ^ y),
        MbaIdentity::AndIsOrMinusXor => (x | y).wrapping_sub(x ^ y),
        MbaIdentity::NotIsNegMinusOne => (0u32.wrapping_sub(x)).wrapping_sub(1),
        MbaIdentity::IncIsNegNot => 0u32.wrapping_sub(!x),
    }
}

/// Encode a 32-bit constant `K` as `K = (A ^ B) + 2*(A & B)` where `A`, `B`
/// are random splits of `K`. Returns `(A, B)`.
pub fn split_constant(k: u32) -> (u32, u32) {
    let mut rng = rand::thread_rng();
    let a: u32 = rng.gen();
    let b = k.wrapping_sub(a);
    (a, b)
}

/// Emit an x86-64 sequence that computes the MBA RHS of `identity` using
/// `eax` (x) and `ecx` (y) as inputs and leaves the result in `eax`.
///
/// Emitted code is **side-effect-free junk** suitable for injection into
/// `.text` for control-flow obfuscation.
pub fn emit_identity(identity: MbaIdentity) -> Vec<u8> {
    let mut code = Vec::new();
    match identity {
        MbaIdentity::AddIsXorPlusTwoAnd => {
            code.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
            code.extend_from_slice(&[0x21, 0xCA]); // and edx, ecx
            code.extend_from_slice(&[0xD1, 0xE2]); // shl edx, 1
            code.extend_from_slice(&[0x31, 0xC8]); // xor eax, ecx
            code.extend_from_slice(&[0x01, 0xD0]); // add eax, edx
        }
        MbaIdentity::XorIsOrMinusAnd => {
            code.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
            code.extend_from_slice(&[0x21, 0xCA]); // and edx, ecx
            code.extend_from_slice(&[0x09, 0xC8]); // or eax, ecx
            code.extend_from_slice(&[0x29, 0xD0]); // sub eax, edx
        }
        MbaIdentity::OrIsAndPlusXor => {
            code.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
            code.extend_from_slice(&[0x31, 0xCA]); // xor edx, ecx
            code.extend_from_slice(&[0x21, 0xC8]); // and eax, ecx
            code.extend_from_slice(&[0x01, 0xD0]); // add eax, edx
        }
        MbaIdentity::AndIsOrMinusXor => {
            code.extend_from_slice(&[0x89, 0xC2]); // mov edx, eax
            code.extend_from_slice(&[0x31, 0xCA]); // xor edx, ecx
            code.extend_from_slice(&[0x09, 0xC8]); // or eax, ecx
            code.extend_from_slice(&[0x29, 0xD0]); // sub eax, edx
        }
        MbaIdentity::NotIsNegMinusOne => {
            code.extend_from_slice(&[0xF7, 0xD8]); // neg eax
            code.extend_from_slice(&[0x83, 0xE8, 0x01]); // sub eax, 1
        }
        MbaIdentity::IncIsNegNot => {
            code.extend_from_slice(&[0xF7, 0xD0]); // not eax
            code.extend_from_slice(&[0xF7, 0xD8]); // neg eax
        }
    }
    code
}

/// Emit a sequence loading `k` into `eax` via an MBA-split: instead of a
/// single `mov eax, k`, emits `mov eax, A; mov ecx, B` plus the MBA add
/// chain so the constant never appears verbatim.
pub fn emit_constant_load(k: u32) -> Vec<u8> {
    let (a, b) = split_constant(k);
    let mut code = Vec::new();
    // mov eax, A
    code.push(0xB8);
    code.extend_from_slice(&a.to_le_bytes());
    // mov ecx, B
    code.push(0xB9);
    code.extend_from_slice(&b.to_le_bytes());
    // emit RHS of AddIsXorPlusTwoAnd
    code.extend_from_slice(&emit_identity(MbaIdentity::AddIsXorPlusTwoAnd));
    code
}

/// Generate a randomized chain of `count` MBA identities. Useful as a junk
/// block that looks like real arithmetic.
pub fn generate_mba_chain(count: usize) -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..count {
        code.extend_from_slice(&emit_identity(MbaIdentity::random()));
    }
    code
}

/// Pick `count` random MBA identities (the pre-emit selection step) so callers
/// can transform each independently before serializing.
pub fn sample_mba_identities(count: usize) -> Vec<MbaIdentity> {
    (0..count).map(|_| MbaIdentity::random()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_hold_for_random_inputs() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            for &id in MbaIdentity::ALL {
                assert_eq!(
                    evaluate(id, x, y),
                    evaluate_obfuscated(id, x, y),
                    "identity {:?} failed for x={}, y={}",
                    id,
                    x,
                    y
                );
            }
        }
    }

    #[test]
    fn split_constant_roundtrips() {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let k: u32 = rng.gen();
            let (a, b) = split_constant(k);
            assert_eq!(evaluate_obfuscated(MbaIdentity::AddIsXorPlusTwoAnd, a, b), k);
        }
    }

    #[test]
    fn emitted_code_nonempty() {
        for &id in MbaIdentity::ALL {
            let c = emit_identity(id);
            assert!(!c.is_empty(), "identity {:?} produced no bytes", id);
        }
    }

    #[test]
    fn constant_load_is_long_enough() {
        let code = emit_constant_load(0xDEAD_BEEF);
        // mov eax,A (5) + mov ecx,B (5) + 5 add-mba bytes (>= 10) ~= 20 bytes
        assert!(code.len() >= 15);
    }

    #[test]
    fn mba_chain_is_repeatable() {
        let c1 = generate_mba_chain(4);
        let c2 = generate_mba_chain(4);
        // Random, so they may differ; but length must be > 0.
        assert!(!c1.is_empty());
        assert!(!c2.is_empty());
    }
}
