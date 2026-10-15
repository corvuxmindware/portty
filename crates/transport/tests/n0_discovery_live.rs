//! Live check against n0's public relays and pkarr server, so it is `#[ignore]`d.
//! Run it after changing how `build_endpoint` publishes or looks peers up:
//!
//! ```text
//! cargo test -p portty-transport --test n0_discovery_live -- --ignored
//! ```
//!
//! The phone's compact QR (`portty3:`) carries only the host's NodeId, so a
//! first pair stands or falls with finding the host through discovery.
//! `build_endpoint` looks peers up over HTTPS only (no plain-DNS query that
//! would show the NodeId to the network's resolver); this proves that is enough.

use std::time::Duration;

use iroh::{EndpointAddr, RelayMode};
use portty_transport::{build_endpoint, Identity, SYNC_ALPN};
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the internet: talks to n0's public relays and dns.iroh.link"]
async fn a_bare_node_id_is_found_through_https_discovery() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("iroh=info,portty_transport=debug")
        .with_writer(std::io::stderr)
        .try_init();

    let host_dir = tempdir().unwrap();
    let client_dir = tempdir().unwrap();
    let host_id = Identity::load_or_create(host_dir.path()).unwrap();
    let client_id = Identity::load_or_create(client_dir.path()).unwrap();
    let host = build_endpoint(&host_id, RelayMode::Default).await.unwrap();
    let client = build_endpoint(&client_id, RelayMode::Default)
        .await
        .unwrap();

    // The host publishes its record once it has a home relay.
    tokio::time::timeout(Duration::from_secs(30), host.online())
        .await
        .expect("the host never reached an n0 relay");

    let server = host.clone();
    let accepting = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            if let Ok(connection) = incoming.await {
                return connection.remote_id();
            }
        }
        panic!("the host endpoint closed before a connection arrived");
    });

    // No relay URL and no addresses: exactly what a compact QR gives the phone.
    // Publishing can trail `online()` by a moment, so retry for about a minute.
    let target = EndpointAddr::new(host.id());
    let mut last_error = String::new();
    let mut connection = None;
    for _ in 0..6 {
        match tokio::time::timeout(
            Duration::from_secs(15),
            client.connect(target.clone(), SYNC_ALPN),
        )
        .await
        {
            Ok(Ok(established)) => {
                connection = Some(established);
                break;
            }
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "connect timed out".into(),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let connection =
        connection.unwrap_or_else(|| panic!("never found the host by NodeId alone: {last_error}"));
    assert_eq!(connection.remote_id(), host.id());

    let seen_by_host = tokio::time::timeout(Duration::from_secs(15), accepting)
        .await
        .expect("the host never finished accepting")
        .unwrap();
    assert_eq!(seen_by_host, client.id());

    connection.close(0u8.into(), b"done");
    tokio::join!(host.close(), client.close());
}
