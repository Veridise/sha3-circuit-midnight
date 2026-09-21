//! Implementation of keccak/sha3 hash functions using packed arithmetic

mod constants;
pub mod instructions;
#[cfg(feature = "extraction")]
mod lookup_callbacks;
#[cfg(not(doctest))]
pub mod packed_chip;
pub mod sha3_256_gadget;

#[cfg(feature = "extraction")]
pub fn harnesses() -> impl Iterator<Item = &'static haloumi_extractor::Harness> {
    haloumi_extractor::inventory::iter::<haloumi_extractor::Harness>()
}
