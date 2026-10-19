#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = nos_ospf::packet::decode(data, &nos_ospf::packet::AuthPolicy::None);
    let _ = nos_ospf::lsa::decode_lsa(data);
});
