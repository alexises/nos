//! Read half of a push connection. Push clients only write; the consumer
//! never does, so any read result means it closed (restarted) and lost
//! what it was told: reconnect and send a fresh `Full` (#718).

use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, ReadHalf, WriteHalf};

pub struct PushReader<S = nos_pki::Stream>(ReadHalf<S>);

/// Splits a connected stream into its write half and a [`PushReader`].
pub fn split<S: AsyncRead + tokio::io::AsyncWrite>(stream: S) -> (WriteHalf<S>, PushReader<S>) {
    let (r, w) = tokio::io::split(stream);
    (w, PushReader(r))
}

impl<S: AsyncRead + Unpin> PushReader<S> {
    /// Whether the consumer closed the connection (checked without waiting).
    pub fn closed(&mut self) -> bool {
        let mut buf = [0u8; 64];
        matches!(self.0.read(&mut buf).now_or_never(), Some(Ok(0) | Err(_)))
    }

    /// Resolves when the consumer closes (or sends anything). Cancel-safe.
    pub async fn eof(&mut self) {
        let mut buf = [0u8; 64];
        let _ = self.0.read(&mut buf).await;
    }
}

/// Resolves when any of `readers` sees EOF; never when there are none.
pub async fn any_eof<'a, S: AsyncRead + Unpin + 'a>(
    readers: impl Iterator<Item = &'a mut PushReader<S>>,
) {
    let reads: Vec<_> = readers.map(|r| Box::pin(r.eof())).collect();
    if reads.is_empty() {
        std::future::pending::<()>().await;
    }
    futures::future::select_all(reads).await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn open_is_not_closed_and_drop_is_eof() {
        let (a, b) = tokio::io::duplex(64);
        let (_w, mut r) = split(a);
        assert!(!r.closed());
        assert!(tokio::time::timeout(Duration::from_millis(20), r.eof())
            .await
            .is_err());
        drop(b);
        tokio::time::timeout(Duration::from_secs(1), r.eof())
            .await
            .unwrap();
        assert!(r.closed());
    }

    #[tokio::test]
    async fn any_eof_pending_when_empty_and_wakes_on_close() {
        let none = std::iter::empty::<&mut PushReader<tokio::io::DuplexStream>>();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), any_eof(none))
                .await
                .is_err()
        );
        let (a, mut b) = tokio::io::duplex(64);
        let (_w, mut r) = split(a);
        b.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), any_eof([&mut r].into_iter()))
            .await
            .unwrap();
    }
}
