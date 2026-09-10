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
