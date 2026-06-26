#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
pub mod maps;
#[cfg(not(test))]
pub mod xdp;

pub mod pure;
