//! A basic ZipReader/Writer crate

#![warn(missing_docs)]

pub use crate::compression::CompressionMethod;
pub use crate::read::ZipArchive;
pub use crate::types::DateTime;
pub use crate::write::ZipWriter;

mod compression;
mod cp437;
mod crc32;
pub mod read;
pub mod result;
mod spec;
#[cfg(feature = "tokio-02")]
pub mod tokio;
mod types;
pub mod write;
mod zipcrypto;
