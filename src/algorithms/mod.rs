//! This module contains built-in implementations of the [`Hasher`]
//!
//! [`Hasher`]: crate::Hasher
mod keccak256;

pub use keccak256::Keccak256Algorithm as Keccak256;
