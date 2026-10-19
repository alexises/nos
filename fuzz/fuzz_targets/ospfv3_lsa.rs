#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = nos_ospfv3::lsa::decode_lsa(data);
});
