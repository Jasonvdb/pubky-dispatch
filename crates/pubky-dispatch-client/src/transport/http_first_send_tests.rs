// Loopback-only TLS certificates for the wallet and phone signing keys in spec/vectors/keys.json,
// made by `python3 tools/loopback-tls-fixtures.py <wallet signing_secret_hex>
// <phone signing_secret_hex> "Dispatch loopback test CA"`, which gives the same bytes for the
// same keys: run it again whenever those keys change.
const CA: &str = concat!(
    "MIIBXDCCAQ6gAwIBAgIBATAFBgMrZXAwJDEiMCAGA1UEAwwZRGlzcGF0Y2ggbG9vcGJhY2sgdGVzdCBD",
    "QTAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MDEwMTAwMDAwMFowJDEiMCAGA1UEAwwZRGlzcGF0Y2ggbG9v",
    "cGJhY2sgdGVzdCBDQTAqMAUGAytlcAMhADwkUNOaAR5_sIv-r-wdS373MieuXdI9L-Fn6eT765m0o2Mw",
    "YTAdBgNVHQ4EFgQUm6bZ8TEIB7ReK4KNrfhoE2Qu3HQwHwYDVR0jBBgwFoAUm6bZ8TEIB7ReK4KNrfho",
    "E2Qu3HQwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAgQwBQYDK2VwA0EA-yRc8Nac4BRXlL27",
    "M6lLyThMfJR-D1huI1KNmle0_PlRfdbRGZo6I0L-oY0CV2657OxMiSs8QN15Ra2gxY62Dg",
);
const SERVER: &str = concat!(
    "MIIBdjCCASigAwIBAgIBAjAFBgMrZXAwJDEiMCAGA1UEAwwZRGlzcGF0Y2ggbG9vcGJhY2sgdGVzdCBD",
    "QTAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MCow",
    "BQYDK2VwAyEAoNhCqxbOHNl_2YFoPJJe2YR8UcLSIfztSblgO8phLdyjgYwwgYkwDAYDVR0TAQH_BAIw",
    "ADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJbG9jYWxob3N0",
    "MB0GA1UdDgQWBBR_0LL05txbKM7N8eiIYUNlzbNGazAfBgNVHSMEGDAWgBSbptnxMQgHtF4rgo2t-GgT",
    "ZC7cdDAFBgMrZXADQQCau0uKHsoCqP2FfIbgAkdozUYAVCa31ouY5FPFEtHEVhxO7TtwGZealxUS0BB8",
    "pt-o2OLV81UGIz51UXyZhrsG",
);
const KEY: &str = "MC4CAQAwBQYDK2VwBCIEIL6xIVFHt1vgUe5_e1khhk53Y5sgJz2sw2NWssVsxasT";

use super::*;
use crate::clock::TestClock;
use crate::transport::FirstSend;
use pubky_dispatch_core::enc::unb64;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};

async fn send_after_connect(expire: bool) {
    let clock = Arc::new(TestClock::new(1_000));
    let first = FirstSend::new(clock.clone(), 1_000, 0, 601_000);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(unb64(SERVER).unwrap())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(unb64(KEY).unwrap())),
    )
    .unwrap();
    let serve = async {
        let (socket, _) = listener.accept().await.unwrap();
        if expire {
            clock.set_ms(601_000);
        }
        let Ok(mut tls) = TlsAcceptor::from(Arc::new(server)).accept(socket).await else {
            return Vec::new();
        };
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        while !request.ends_with(b"exact-operation-body") {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
        }
        if !request.is_empty() {
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        }
        request
    };
    let mut http =
        HttpTransport::without_address_checks_for_loopback_tests(HttpConfig::default()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(unb64(CA).unwrap())).unwrap();
    http.first_send_tls = HttpTransport::first_send_tls(roots).unwrap();
    let request = Request {
        method: "POST".into(),
        origin: format!("https://localhost:{port}"),
        path_and_query: "/v1/account/ops".into(),
        headers: Vec::new(),
        body: b"exact-operation-body".to_vec(),
        timeout: TimeoutClass::Ordinary,
    };
    let (answer, seen) = tokio::join!(http.send_before(request, &first), serve);
    if expire {
        assert!(matches!(answer, Err(TransportError::FirstSendExpired)));
        assert!(seen.is_empty());
    } else {
        assert_eq!(answer.unwrap().body, b"ok");
        assert!(seen.starts_with(b"POST /v1/account/ops HTTP/1.1\r\n"));
        assert!(seen.ends_with(b"exact-operation-body"));
    }
}

#[tokio::test]
async fn test_native_https_transmits_guarded_operation_body() {
    send_after_connect(false).await;
}

#[tokio::test]
async fn test_native_https_connection_delayed_until_cutoff_carries_no_post() {
    send_after_connect(true).await;
}
