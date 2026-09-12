/// Returns a `garde` error if `value` appears more than once in `items`
/// as identified by the `key` extractor.
///
/// Reusable for any list in the config tree where elements must be unique.
pub fn unique_in<T, K>(value: &K, items: &[T], key: impl Fn(&T) -> &K) -> garde::Result
where
    K: PartialEq,
{
    if items.iter().filter(|i| key(i) == value).count() > 1 {
        return Err(garde::Error::new("must be unique"));
    }
    Ok(())
}

/// Returns a `garde` error unless `value` is composed only of ASCII
/// letters, digits, and hyphens, with no leading or trailing hyphen.
///
/// Not RFC-1123-exhaustive (no per-label length limit, no leading-digit
/// restriction) — just enough to keep obviously malformed hostnames out.
pub fn hostname_charset(value: &str) -> garde::Result {
    let valid_chars = value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let valid_edges = !value.starts_with('-') && !value.ends_with('-');
    if !valid_chars || !valid_edges {
        return Err(garde::Error::new(
            "must contain only ASCII letters, digits, and hyphens, and must not start or end with a hyphen",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_charset_accepts_mixed_case_and_hyphen() {
        assert!(hostname_charset("Router-1").is_ok());
    }

    #[test]
    fn hostname_charset_rejects_leading_hyphen() {
        assert!(hostname_charset("-router").is_err());
    }

    #[test]
    fn hostname_charset_rejects_trailing_hyphen() {
        assert!(hostname_charset("router-").is_err());
    }

    #[test]
    fn hostname_charset_rejects_underscore() {
        assert!(hostname_charset("router_1").is_err());
    }

    #[test]
    fn hostname_charset_rejects_space() {
        assert!(hostname_charset("router 1").is_err());
    }
}
