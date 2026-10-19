#![no_main]
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let Some((&version, rest)) = data.split_first() else {
        return;
    };
    let mut codec = nos_bgp::rpki::rtr::RtrCodec { version };
    let mut buf = bytes::BytesMut::from(rest);
    while let Ok(Some(_)) = codec.decode(&mut buf) {}
});
