// Loopback-only TLS certificates for the wallet and phone signing keys in spec/vectors/keys.json.
const CA: &str = concat!(
    "MIIBWDCCAQqgAwIBAgIBATAFBgMrZXAwIjEgMB4GA1UEAwwXU3dpdGNoIGxvb3BiYWNrIHRlc3QgQ0Ew",
    "IBcNMjAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBaMCIxIDAeBgNVBAMMF1N3aXRjaCBsb29wYmFj",
    "ayB0ZXN0IENBMCowBQYDK2VwAyEAzBRPZWGzwLZBL6JkbhAtcqenmOAvuaEARhizaATmEOajYzBhMB0G",
    "A1UdDgQWBBTqqipF2qFJxhuTvkCFHGdAp3OCwTAfBgNVHSMEGDAWgBTqqipF2qFJxhuTvkCFHGdAp3OC",
    "wTAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwICBDAFBgMrZXADQQDVykuIgpFspV3RgaKLOd0i",
    "-YKbGVk3FwmY92Mq0Yq0s5RQ_0QXrBkUzb_o7CBpjpIEPjz6m1Hg0XoqSLF7mykL",
);
const SERVER: &str = concat!(
    "MIIBdDCCASagAwIBAgIBAjAFBgMrZXAwIjEgMB4GA1UEAwwXU3dpdGNoIGxvb3BiYWNrIHRlc3QgQ0Ew",
    "IBcNMjAwMTAxMDAwMDAwWhgPMjA5OTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUG",
    "AytlcAMhABnSSlLssvo6fPyi1aXbg-IV0iswlcXyWSU6vgL8YcSUo4GMMIGJMAwGA1UdEwEB_wQCMAAw",
    "DgYDVR0PAQH_BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAd",
    "BgNVHQ4EFgQU4UrZ4WwkDnVUHvMFmk8y-Y8hhmgwHwYDVR0jBBgwFoAU6qoqRdqhScYbk75AhRxnQKdz",
    "gsEwBQYDK2VwA0EA8HTGnmCQAcgASfsuCUGz6ch5k9NyEIk_DjqXgAImHMe-lQkiF_iH01PRRrELHVKC",
    "u9egYYBklU-y0Qc_TIv4Dg",
);
const KEY: &str = "MC4CAQAwBQYDK2VwBCIEILtKd7DIC20ScN6cVvnDa37RBhZFANtTBZrJrD8GkZs6";

use super::*;
use crate::clock::TestClock;
use crate::transport::FirstSend;
use pubky_switch_core::enc::unb64;
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
