//! Opaque keyset-pagination cursors (#714): the URL-safe base64 (no padding)
//! of a cursor's postcard bytes. Clients pass the text back verbatim.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};

/// A cursor string that is not valid base64 postcard of the expected type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid pagination cursor")]
pub struct BadCursor;

/// The opaque text of `cursor`.
pub fn encode<T: Serialize>(cursor: &T) -> String {
    URL_SAFE_NO_PAD.encode(postcard::to_allocvec(cursor).unwrap_or_default())
}

/// Encoded size of `row` on the wire, for budgeting a page.
pub fn wire_len<T: Serialize>(row: &T) -> usize {
    postcard::to_allocvec(row).map_or(0, |v| v.len())
}

/// Inverse of [`encode`]; trailing bytes are refused.
pub fn decode<T: DeserializeOwned>(text: &str) -> Result<T, BadCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| BadCursor)?;
    let (v, rest) = postcard::take_from_bytes(&bytes).map_err(|_| BadCursor)?;
    if rest.is_empty() {
        Ok(v)
    } else {
        Err(BadCursor)
    }
}

#[cfg(test)]
mod tests {
    use crate::BgpRouteCursor;

    #[test]
    fn cursor_text_round_trips_and_is_url_safe() {
        for peer in [None, Some("2001:db8::1".parse().unwrap())] {
            let c = BgpRouteCursor {
                prefix: "10.0.0.0/8".parse().unwrap(),
                peer,
                path_id: 7,
            };
            let t = c.to_string();
            assert!(t
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            assert_eq!(t.parse::<BgpRouteCursor>().unwrap(), c);
        }
    }

    #[test]
    fn garbage_and_trailing_bytes_are_refused() {
        assert!("nope!".parse::<BgpRouteCursor>().is_err());
        assert!("".parse::<BgpRouteCursor>().is_err());
        let mut t = BgpRouteCursor {
            prefix: "10.0.0.0/8".parse().unwrap(),
            peer: None,
            path_id: 0,
        }
        .to_string();
        t.push_str("AA");
        assert!(t.parse::<BgpRouteCursor>().is_err());
    }

    #[test]
    fn cursors_order_local_first_then_prefix_peer_id() {
        let c = |p: &str, peer: Option<&str>, id| BgpRouteCursor {
            prefix: p.parse().unwrap(),
            peer: peer.map(|s| s.parse().unwrap()),
            path_id: id,
        };
        assert!(c("10.0.0.0/8", None, 5) < c("10.0.0.0/8", Some("1.1.1.1"), 0));
        assert!(c("10.0.0.0/8", Some("1.1.1.1"), 0) < c("10.0.0.0/8", Some("1.1.1.1"), 1));
        assert!(c("10.0.0.0/8", Some("9.9.9.9"), 9) < c("11.0.0.0/8", None, 0));
    }
}
