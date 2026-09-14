//! Implementation of keccak/sha3 hash functions using packed arithmetic

mod constants;
pub mod instructions;
#[cfg(not(doctest))]
pub mod packed_chip;
pub mod sha3_256_gadget;

#[cfg(feature = "extraction")]
haloumi::__impl_harnesses_root_function!(haloumi_extractor, harnesses);

/// Temporary location of the harnesses until we have the discovery macros.
pub mod harness_impls {}
