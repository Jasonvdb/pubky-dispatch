//! Protected response headers through the production HTTP transport.
#![cfg(all(feature = "http", feature = "test-support"))]
#![allow(clippy::unwrap_used)]
use pubky_switch_client::client::{SentRequest, check_response};
use pubky_switch_client::transport::{HttpConfig, HttpTransport, Request, TimeoutClass, Transport};
use pubky_switch_core::http::{ResponseParts, sign_response};
use std::io::{Read, Write};

#[tokio::test]
async fn test_http_response_unreadable_protected_headers_fail() {
    let mut outcomes = Vec::new();
    for extra in [
        b"".as_slice(),
        b"Switch-Head: \x80\r\n",
        b"Switch-Server-Time: \x80\r\n",
        b"Switch-Service-Signature: \x80\r\n",
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let request = Request {
            method: "POST".into(),
            origin,
            path_and_query: "/v1/x/connect".into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: TimeoutClass::default(),
        };
        let sent = SentRequest::of(&request);
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let time = "2026-01-01T00:00:00.000Z";
        let body = b"{}";
        let signature = sign_response(
            &key,
            &ResponseParts {
                status: 200,
                request: sent.received(true),
                server_time: time,
                head: None,
                body,
            },
        );
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nSwitch-Server-Time: {time}\r\nSwitch-Service-Signature: {}\r\n", pubky_switch_core::enc::b64(&signature)).into_bytes();
        raw.extend_from_slice(extra);
        raw.extend_from_slice(b"\r\n{}");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut input = [0; 4096];
            socket.read(&mut input).unwrap();
            socket.write_all(&raw).unwrap();
        });
        let transport =
            HttpTransport::without_address_checks_for_loopback_tests(HttpConfig::default())
                .unwrap();
        let result = transport.send(request).await;
        server.join().unwrap();
        outcomes.push(match result {
            Ok(response) => {
                check_response(&key.verifying_key().to_bytes(), &[1; 32], &sent, &response).is_ok()
            }
            Err(_) => false,
        });
    }
    assert_eq!(
        outcomes,
        vec![true, false, false, false],
        "signed answer, invalid head, duplicate unreadable time, duplicate unreadable signature"
    );
}
