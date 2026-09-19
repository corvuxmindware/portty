#![no_main]

use libfuzzer_sys::fuzz_target;
use portty_transport::{decode_ticket, decode_ticket_secret};

fuzz_target!(|data: &[u8]| {
    let Ok(ticket) = std::str::from_utf8(data) else {
        return;
    };
    let _ = decode_ticket(ticket);
    let _ = decode_ticket_secret(ticket);
});
