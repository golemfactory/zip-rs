//! Structs for reading a ZIP archive

use crate::compression::CompressionMethod;
use crate::result::{ZipError, ZipResult};
use crate::spec;
use crate::tokio::crc32::Crc32Reader;
use crate::tokio::zipcrypto::ZipCryptoReader;
use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, BufReader, ReadBuf, Take};

use crate::cp437::FromCp437;
use crate::types::{DateTime, System, ZipFileData};
use tokio_byteorder::{AsyncReadBytesExt, LittleEndian};

#[cfg(feature = "bzip2")]
use async_compression::tokio::bufread::BzDecoder;
#[cfg(feature = "deflate")]
use async_compression::tokio::bufread::DeflateDecoder;
#[cfg(feature = "deflate-zlib")]
use async_compression::tokio::bufread::ZlibDecoder;

mod ffi {
    pub const S_IFDIR: u32 = 0o0040000;
    pub const S_IFREG: u32 = 0o0100000;
}

enum CryptoReader<'a> {
    Plaintext(Take<&'a mut (dyn AsyncRead + Unpin)>),
    ZipCrypto(ZipCryptoReader<Take<&'a mut (dyn AsyncRead + Unpin)>>),
}

impl<'a> AsyncRead for CryptoReader<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            CryptoReader::Plaintext(r) => Pin::new(r).poll_read(cx, buf),
            CryptoReader::ZipCrypto(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl<'a> CryptoReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> Take<&'a mut (dyn AsyncRead + Unpin)> {
        match self {
            CryptoReader::Plaintext(r) => r,
            CryptoReader::ZipCrypto(r) => r.into_inner(),
        }
    }
}

enum ZipFileReader<'a> {
    NoReader,
    Stored(Crc32Reader<CryptoReader<'a>>),
    #[cfg(feature = "deflate")]
    Deflated(Crc32Reader<DeflateDecoder<BufReader<CryptoReader<'a>>>>),
    #[cfg(feature = "deflate-zlib")]
    Deflated(Crc32Reader<ZlibDecoder<BufReader<CryptoReader<'a>>>>),
    #[cfg(feature = "bzip2")]
    Bzip2(Crc32Reader<BzDecoder<BufReader<CryptoReader<'a>>>>),
}

impl<'a> AsyncRead for ZipFileReader<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Stored(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(any(feature = "deflate", feature = "deflate-zlib"))]
            ZipFileReader::Deflated(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl<'a> ZipFileReader<'a> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> Take<&'a mut (dyn AsyncRead + Unpin)> {
        match self {
            ZipFileReader::NoReader => panic!("ZipFileReader was in an invalid state"),
            ZipFileReader::Stored(r) => r.into_inner().into_inner(),
            #[cfg(any(feature = "deflate", feature = "deflate-zlib"))]
            ZipFileReader::Deflated(r) => r.into_inner().into_inner().into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            ZipFileReader::Bzip2(r) => r.into_inner().into_inner().into_inner().into_inner(),
        }
    }
}

/// A struct for reading a zip file
pub struct ZipFile<'a> {
    data: Cow<'a, ZipFileData>,
    reader: ZipFileReader<'a>,
}

fn make_reader<'a>(
    compression_method: crate::compression::CompressionMethod,
    crc32: u32,
    reader: Take<&'a mut (dyn AsyncRead + Unpin)>,
    password: Option<&[u8]>,
) -> ZipResult<ZipFileReader<'a>> {
    let reader = match password {
        None => CryptoReader::Plaintext(reader),
        Some(password) => CryptoReader::ZipCrypto(ZipCryptoReader::new(reader, password)),
    };

    match compression_method {
        CompressionMethod::Stored => Ok(ZipFileReader::Stored(Crc32Reader::new(reader, crc32))),
        #[cfg(feature = "deflate")]
        CompressionMethod::Deflated => {
            let deflate_reader = DeflateDecoder::new(BufReader::new(reader));
            Ok(ZipFileReader::Deflated(Crc32Reader::new(
                deflate_reader,
                crc32,
            )))
        }
        #[cfg(feature = "deflate-zlib")]
        CompressionMethod::Deflated => {
            let deflate_reader = ZlibDecoder::new(BufReader::new(reader));
            Ok(ZipFileReader::Deflated(Crc32Reader::new(
                deflate_reader,
                crc32,
            )))
        }
        #[cfg(feature = "bzip2")]
        CompressionMethod::Bzip2 => {
            let bzip2_reader = BzDecoder::new(BufReader::new(reader));
            Ok(ZipFileReader::Bzip2(Crc32Reader::new(bzip2_reader, crc32)))
        }
        _ => unsupported_zip_error("Compression method not supported"),
    }
}

fn unsupported_zip_error<T>(detail: &'static str) -> ZipResult<T> {
    Err(ZipError::UnsupportedArchive(detail))
}

async fn parse_extra_field(file: &mut ZipFileData, data: &[u8]) -> ZipResult<()> {
    let mut reader = std::io::Cursor::new(data);

    while (reader.position() as usize) < data.len() {
        let kind = reader.read_u16::<LittleEndian>().await?;
        let len = reader.read_u16::<LittleEndian>().await?;
        let mut len_left = len as i64;
        // Zip64 extended information extra field
        if kind == 0x0001 {
            if file.uncompressed_size == 0xFFFFFFFF {
                file.uncompressed_size = reader.read_u64::<LittleEndian>().await?;
                len_left -= 8;
            }
            if file.compressed_size == 0xFFFFFFFF {
                file.compressed_size = reader.read_u64::<LittleEndian>().await?;
                len_left -= 8;
            }
            if file.header_start == 0xFFFFFFFF {
                file.header_start = reader.read_u64::<LittleEndian>().await?;
                len_left -= 8;
            }
            // Unparsed fields:
            // u32: disk start number
        }

        if len_left > 0 {
            let mut buf = vec![0; len_left as usize];
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buf).await?;
        }
    }
    Ok(())
}

/// Methods for retrieving information on zip files
impl<'a> ZipFile<'a> {
    /// Get the version of the file
    pub fn version_made_by(&self) -> (u8, u8) {
        (
            self.data.version_made_by / 10,
            self.data.version_made_by % 10,
        )
    }

    /// Get the name of the file
    pub fn name(&self) -> &str {
        &self.data.file_name
    }

    /// Get the name of the file, in the raw (internal) byte representation.
    pub fn name_raw(&self) -> &[u8] {
        &self.data.file_name_raw
    }

    /// Get the name of the file in a sanitized form. It truncates the name to the first NULL byte,
    /// removes a leading '/' and removes '..' parts.
    pub fn sanitized_name(&self) -> ::std::path::PathBuf {
        self.data.file_name_sanitized()
    }

    /// Get the comment of the file
    pub fn comment(&self) -> &str {
        &self.data.file_comment
    }

    /// Get the compression method used to store the file
    pub fn compression(&self) -> CompressionMethod {
        self.data.compression_method
    }

    /// Get the size of the file in the archive
    pub fn compressed_size(&self) -> u64 {
        self.data.compressed_size
    }

    /// Get the size of the file when uncompressed
    pub fn size(&self) -> u64 {
        self.data.uncompressed_size
    }

    /// Get the time the file was last modified
    pub fn last_modified(&self) -> DateTime {
        self.data.last_modified_time
    }
    /// Returns whether the file is actually a directory
    pub fn is_dir(&self) -> bool {
        self.name()
            .chars()
            .rev()
            .next()
            .map_or(false, |c| c == '/' || c == '\\')
    }

    /// Returns whether the file is a regular file
    pub fn is_file(&self) -> bool {
        !self.is_dir()
    }

    /// Get unix mode for the file
    pub fn unix_mode(&self) -> Option<u32> {
        if self.data.external_attributes == 0 {
            return None;
        }

        match self.data.system {
            System::Unix => Some(self.data.external_attributes >> 16),
            System::Dos => {
                // Interpret MSDOS directory bit
                let mut mode = if 0x10 == (self.data.external_attributes & 0x10) {
                    ffi::S_IFDIR | 0o0775
                } else {
                    ffi::S_IFREG | 0o0664
                };
                if 0x01 == (self.data.external_attributes & 0x01) {
                    // Read-only bit; strip write permissions
                    mode &= 0o0555;
                }
                Some(mode)
            }
            _ => None,
        }
    }

    /// Get the CRC32 hash of the original file
    pub fn crc32(&self) -> u32 {
        self.data.crc32
    }

    /// Get the starting offset of the data of the compressed file
    pub fn data_start(&self) -> u64 {
        self.data.data_start
    }

    /// Get the starting offset of the zip header for this file
    pub fn header_start(&self) -> u64 {
        self.data.header_start
    }

    /// Exhaust the remaining buffer and position the reader to the next file
    pub async fn exhaust(&mut self) {
        // self.data is Owned, this reader is constructed by a streaming reader.
        // In this case, we want to exhaust the reader so that the next file is accessible.
        if let Cow::Owned(_) = self.data {
            let mut buffer = [0; 1 << 16];

            // Get the inner `Take` reader so all decryption, decompression and CRC calculation is skipped.
            let inner = ::std::mem::replace(&mut self.reader, ZipFileReader::NoReader);
            let mut reader = inner.into_inner();

            loop {
                match tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await {
                    Ok(0) => break,
                    Ok(_) => (),
                    Err(e) => panic!(
                        "Could not consume all of the output of the current ZipFile: {:?}",
                        e
                    ),
                }
            }
        }
    }
}

impl<'a> AsyncRead for ZipFile<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.get_mut().reader);
        r.poll_read(cx, buf)
    }
}

/// Read ZipFile structures from a non-seekable reader.
///
/// This is an alternative method to read a zip file. If possible, use the ZipArchive functions
/// as some information will be missing when reading this manner.
///
/// Reads a file header from the start of the stream. Will return `Ok(Some(..))` if a file is
/// present at the start of the stream. Returns `Ok(None)` if the start of the central directory
/// is encountered. No more files should be read after this.
///
/// The Drop implementation of ZipFile ensures that the reader will be correctly positioned after
/// the structure is done.
///
/// Missing fields are:
/// * `comment`: set to an empty string
/// * `data_start`: set to 0
/// * `external_attributes`: `unix_mode()`: will return None
pub async fn read_zipfile_from_stream<'a, R: AsyncRead + Unpin>(
    reader: &'a mut R,
) -> ZipResult<Option<ZipFile<'_>>> {
    let signature = reader.read_u32::<LittleEndian>().await?;

    match signature {
        spec::LOCAL_FILE_HEADER_SIGNATURE => (),
        spec::CENTRAL_DIRECTORY_HEADER_SIGNATURE => return Ok(None),
        _ => return Err(ZipError::InvalidArchive("Invalid local file header")),
    }

    let version_made_by = reader.read_u16::<LittleEndian>().await?;
    let flags = reader.read_u16::<LittleEndian>().await?;
    let encrypted = flags & 1 == 1;
    let is_utf8 = flags & (1 << 11) != 0;
    let using_data_descriptor = flags & (1 << 3) != 0;
    #[allow(deprecated)]
    let compression_method = CompressionMethod::from_u16(reader.read_u16::<LittleEndian>().await?);
    let last_mod_time = reader.read_u16::<LittleEndian>().await?;
    let last_mod_date = reader.read_u16::<LittleEndian>().await?;
    let crc32 = reader.read_u32::<LittleEndian>().await?;
    let compressed_size = reader.read_u32::<LittleEndian>().await?;
    let uncompressed_size = reader.read_u32::<LittleEndian>().await?;
    let file_name_length = reader.read_u16::<LittleEndian>().await? as usize;
    let extra_field_length = reader.read_u16::<LittleEndian>().await? as usize;

    let mut file_name_raw = vec![0; file_name_length];
    tokio::io::AsyncReadExt::read_exact(reader, &mut file_name_raw).await?;
    let mut extra_field = vec![0; extra_field_length];
    tokio::io::AsyncReadExt::read_exact(reader, &mut extra_field).await?;

    let file_name = match is_utf8 {
        true => String::from_utf8_lossy(&*file_name_raw).into_owned(),
        false => file_name_raw.clone().from_cp437(),
    };

    let mut result = ZipFileData {
        system: System::from_u8((version_made_by >> 8) as u8),
        version_made_by: version_made_by as u8,
        encrypted,
        compression_method,
        last_modified_time: DateTime::from_msdos(last_mod_date, last_mod_time),
        crc32,
        compressed_size: compressed_size as u64,
        uncompressed_size: uncompressed_size as u64,
        file_name,
        file_name_raw,
        file_comment: String::new(), // file comment is only available in the central directory
        // header_start and data start are not available, but also don't matter, since seeking is
        // not available.
        header_start: 0,
        data_start: 0,
        // The external_attributes field is only available in the central directory.
        // We set this to zero, which should be valid as the docs state 'If input came
        // from standard input, this field is set to zero.'
        external_attributes: 0,
    };

    match parse_extra_field(&mut result, &extra_field).await {
        Ok(..) | Err(ZipError::Io(..)) => {}
        Err(e) => return Err(e),
    }

    if encrypted {
        return unsupported_zip_error("Encrypted files are not supported");
    }
    if using_data_descriptor {
        return unsupported_zip_error("The file length is not available in the local header");
    }

    let limit_reader = tokio::io::AsyncReadExt::take(
        reader as &'a mut (dyn AsyncRead + Unpin),
        result.compressed_size as u64,
    );

    let result_crc32 = result.crc32;
    let result_compression_method = result.compression_method;
    Ok(Some(ZipFile {
        data: Cow::Owned(result),
        reader: make_reader(result_compression_method, result_crc32, limit_reader, None)?,
    }))
}

#[cfg(test)]
mod test {
    use super::read_zipfile_from_stream;

    #[tokio::test]
    async fn zip_read_streaming() {
        let src = include_bytes!("../../tests/data/mimetype.zip");
        let vec = Vec::from(src.as_ref());
        let mut reader = std::io::Cursor::new(vec);
        loop {
            match read_zipfile_from_stream(&mut reader).await.unwrap() {
                Some(mut result) => result.exhaust().await,
                None => break,
            }
        }
    }
}
