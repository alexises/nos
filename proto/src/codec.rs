use std::marker::PhantomData;

use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};
use tokio_util::codec::{Decoder, Encoder};

/// Framed codec for IPC messages over a Unix socket.
///
/// Wire format: 4-byte little-endian length prefix followed by a postcard-encoded payload.
/// A single `IpcCodec<T>` instance handles both encoding and decoding of type `T`.
pub struct IpcCodec<T>(PhantomData<T>);

impl<T> Default for IpcCodec<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T: Serialize> Encoder<T> for IpcCodec<T> {
    type Error = std::io::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = postcard::to_allocvec(&item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let len = u32::try_from(payload.len())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        dst.put_u32_le(len);
        dst.put_slice(&payload);
        Ok(())
    }
}

impl<T: DeserializeOwned> Decoder for IpcCodec<T> {
    type Item = T;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        if src.len() < 4 + len {
            src.reserve(4 + len - src.len());
            return Ok(None);
        }
        src.advance(4);
        let data = src.split_to(len);
        postcard::from_bytes(&data)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // postcard encodes a `u8` as one byte, so `[len=1, 0, 0, 0, v]` is a frame.
    fn dec(buf: &mut BytesMut) -> Result<Option<u8>, std::io::Error> {
        IpcCodec::<u8>::default().decode(buf)
    }

    #[test]
    fn header_split_across_reads_needs_more() {
        for n in 0..4 {
            let mut b = BytesMut::from(&[1u8, 0, 0, 0][..n]);
            assert_eq!(dec(&mut b).unwrap(), None);
            assert_eq!(b.len(), n);
        }
    }

    #[test]
    fn exact_frame_decodes_and_one_byte_short_waits() {
        let mut b = BytesMut::from(&[1u8, 0, 0, 0, 42][..]);
        assert_eq!(dec(&mut b).unwrap(), Some(42));
        assert!(b.is_empty());

        let mut b = BytesMut::from(&[2u8, 0, 0, 0, 42][..]); // len 2, 1 payload byte
        assert_eq!(dec(&mut b).unwrap(), None);
        assert_eq!(&b[..], &[2, 0, 0, 0, 42], "untouched while incomplete");
    }

    #[test]
    fn zero_length_frame_is_a_decode_error_not_need_more() {
        let mut b = BytesMut::from(&[0u8, 0, 0, 0][..]);
        assert!(dec(&mut b).is_err());
        assert!(b.is_empty());
    }

    #[test]
    fn trailing_bytes_stay_for_the_next_frame() {
        let mut b = BytesMut::from(&[1u8, 0, 0, 0, 7, 1, 0][..]);
        assert_eq!(dec(&mut b).unwrap(), Some(7));
        assert_eq!(&b[..], &[1, 0]);
    }
}
