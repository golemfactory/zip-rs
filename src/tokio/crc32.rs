//! Helper module to compute a CRC32 checksum

use crc32fast::Hasher;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

/// Reader that validates the CRC32 when it reaches the EOF.
pub struct Crc32Reader<R: AsyncRead + Unpin> {
    reader: R,
    hasher: Hasher,
    check: u32,
}

impl<R: AsyncRead + Unpin> Crc32Reader<R> {
    /// Get a new Crc32Reader which check the inner reader against checksum.
    pub fn new(reader: R, checksum: u32) -> Crc32Reader<R> {
        Crc32Reader {
            reader,
            hasher: Hasher::new(),
            check: checksum,
        }
    }

    fn check_matches(&self) -> bool {
        self.check == self.hasher.clone().finalize()
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Crc32Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pos = buf.filled().len();

        match { Pin::new(&mut this.reader).poll_read(cx, buf) } {
            Poll::Ready(Ok(())) => match buf.filled().len() - pos {
                0 => {
                    if buf.capacity() == 0 {
                        Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "Empty buffer")))
                    } else if !this.check_matches() {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Invalid checksum",
                        )))
                    } else {
                        Poll::Ready(Ok(()))
                    }
                }
                n => {
                    this.hasher.update(&buf.filled()[pos..pos + n]);
                    Poll::Ready(Ok(()))
                }
            },
            poll => poll,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_empty_reader() {
        let data: &[u8] = b"";
        let mut buf = [0; 1];

        let mut reader = Crc32Reader::new(data, 0);
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);

        let mut reader = Crc32Reader::new(data, 1);
        println!("TEST >>>>");
        assert!(reader
            .read(&mut buf)
            .await
            .unwrap_err()
            .to_string()
            .contains("Invalid checksum"));
    }

    // #[tokio::test]
    // async fn test_byte_by_byte() {
    //     let data: &[u8] = b"1234";
    //     let mut buf = [0; 1];
    //
    //     let mut reader = Crc32Reader::new(data, 0x9be3e0a3);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    //     // Can keep reading 0 bytes after the end
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
    // }
    //
    // #[tokio::test]
    // async fn test_zero_read() {
    //     let data: &[u8] = b"1234";
    //     let mut buf = [0; 5];
    //
    //     let mut reader = Crc32Reader::new(data, 0x9be3e0a3);
    //     assert_eq!(reader.read(&mut buf[..0]).await.unwrap(), 0);
    //     assert_eq!(reader.read(&mut buf).await.unwrap(), 4);
    // }
}
