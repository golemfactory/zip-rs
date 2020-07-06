//! Implementation of the ZipCrypto algorithm
//!
//! The following paper was used to implement the ZipCrypto algorithm:
//! [https://courses.cs.ut.ee/MTAT.07.022/2015_fall/uploads/Main/dmitri-report-f15-16.pdf](https://courses.cs.ut.ee/MTAT.07.022/2015_fall/uploads/Main/dmitri-report-f15-16.pdf)

use crate::zipcrypto::ZipCryptoKeys;
use std::task::Context;
use tokio::io;
use tokio::io::AsyncRead;
use tokio::macros::support::{Pin, Poll};

/// A ZipCrypto reader with unverified password
pub struct ZipCryptoReader<R> {
    reader: R,
    keys: ZipCryptoKeys,
}

impl<R> ZipCryptoReader<R> {
    /// Note: The password is `&[u8]` and not `&str` because the
    /// [zip specification](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.3.TXT)
    /// does not specify password encoding (see function `update_keys` in the specification).
    /// Therefore, if `&str` was used, the password would be UTF-8 and it
    /// would be impossible to decrypt files that were encrypted with a
    /// password byte sequence that is unrepresentable in UTF-8.
    pub fn new(reader: R, password: &[u8]) -> ZipCryptoReader<R> {
        let mut result = ZipCryptoReader {
            reader,
            keys: ZipCryptoKeys::new(),
        };

        // Key the cipher by updating the keys with the password.
        password.iter().for_each(|b| result.keys.update(*b));
        result
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ZipCryptoReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = { Pin::new(&mut this.reader).poll_read(cx, buf) };
        match poll {
            Poll::Ready(Ok(n)) => {
                for byte in buf[..n].iter_mut() {
                    *byte = this.keys.decrypt_byte(*byte);
                }
                Poll::Ready(Ok(n))
            }
            poll => poll,
        }
    }
}

impl<R> ZipCryptoReader<R> {
    /// Consumes this decoder, returning the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}
