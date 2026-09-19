#![no_main]

use libfuzzer_sys::fuzz_target;
use portty_transport::HandshakeMessage;

fuzz_target!(|data: &[u8]| {
    let _ = postcard::from_bytes::<HandshakeMessage>(data);
});
