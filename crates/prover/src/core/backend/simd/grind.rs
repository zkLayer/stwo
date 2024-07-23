use super::SimdBackend;
#[cfg(not(target_arch = "wasm32"))]
use crate::core::channel::Poseidon252Channel;
use crate::core::channel::{Channel, Sha256Channel};
use crate::core::proof_of_work::GrindOps;

impl GrindOps<Sha256Channel> for SimdBackend {
    fn grind(channel: &Sha256Channel, pow_bits: u32) -> u64 {
        let mut nonce = 0;
        loop {
            let mut channel = channel.clone();
            channel.mix_nonce(nonce);
            if channel.trailing_zeros() >= pow_bits {
                return nonce;
            }
            nonce += 1;
        }
    }
}

// TODO(spapini): This is a naive implementation. Optimize it.
#[cfg(not(target_arch = "wasm32"))]
impl GrindOps<Poseidon252Channel> for SimdBackend {
    fn grind(channel: &Poseidon252Channel, pow_bits: u32) -> u64 {
        let mut nonce = 0;
        loop {
            let mut channel = channel.clone();
            channel.mix_nonce(nonce);
            if channel.trailing_zeros() >= pow_bits {
                return nonce;
            }
            nonce += 1;
        }
    }
}
