//! Request targets through the production HTTP conversion (Switch wire 7.1).

use std::sync::atomic::{AtomicUsize, Ordering};

use pubky_switch_core::enc::b64;
use pubky_switch_core::http::{self, RequestHeaders, RequestTarget, ResponseParts, header};
use pubky_switch_core::keys::IdentityKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::ClientError;
use crate::client::{Credentials, SentRequest, SignedRequest, SwitchClient};
use crate::clock::TestClock;

const NOW: u64 = 1_767_225_900_000;
const ORIGIN: &str = "https://switch.example";

/// Records attempts to resolve a host without making a DNS or network call.
#[derive(Default)]
struct NoNetwork(AtomicUsize);

impl reqwest::dns::Resolve for NoNetwork {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(std::io::Error::other("no network in this test").into()) })
    }
}

fn client(origin: &str, transport: Arc<HttpTransport>) -> SwitchClient {
    let key = IdentityKey::from_secret([1; 32]);
    SwitchClient::new(
        origin,
        key.public(),
        Credentials::Signer {
            identity: key.public(),
            key: Arc::new(key),
        },
        Some(IdentityKey::from_secret([5; 32]).public()),
        transport,
        Arc::new(TestClock::new(NOW)),
    )
    .unwrap()
}

fn signed(mut request: Request) -> SignedRequest {
    let key = IdentityKey::from_secret([1; 32]);
    let headers = RequestHeaders {
        timestamp: pubky_switch_core::time::rfc3339(NOW),
        identity: key.id(),
        ..RequestHeaders::default()
    };
    let target = RequestTarget {
        method: &request.method,
        origin: &request.origin,
        path_and_query: &request.path_and_query,
        body: &request.body,
    };
    let signature = http::sign_request(&key, &target, &headers);
    http::verify_request(&key.public(), &target, &headers, &signature).unwrap();
    request.headers = vec![
        Header::new(header::IDENTITY, &headers.identity),
        Header::new(header::TIMESTAMP, &headers.timestamp),
        Header::new(header::SIGNATURE, &b64(&signature)),
    ];
    SignedRequest { request }
}

fn request(origin: &str, method: &str, suffix: &str, bytes: usize) -> Request {
    Request {
        method: method.into(),
        origin: origin.into(),
        path_and_query: format!("/v1/{}/{suffix}", IdentityKey::from_secret([1; 32]).id()),
        headers: Vec::new(),
        body: vec![b'x'; bytes],
        timeout: TimeoutClass::Ordinary,
    }
}

fn no_network() -> (SwitchClient, Arc<NoNetwork>) {
    let resolver = Arc::new(NoNetwork::default());
    let mut transport = HttpTransport::new(HttpConfig::default()).unwrap();
    transport.client = builder(&HttpConfig::default())
        .https_only(true)
        .dns_resolver(resolver.clone())
        .build()
        .unwrap();
    (client(ORIGIN, Arc::new(transport)), resolver)
}

#[tokio::test]
async fn test_http_raw_send_dot_targets_are_rejected_before_connecting() {
    let (client, resolver) = no_network();
    let mut outcomes = Vec::new();
    for suffix in [
        "ops/../inbox",
        "ops/%2e%2E/inbox",
        "ops/.%2e/inbox",
        "ops/%2E./inbox",
        "./inbox",
        "%2e/inbox",
    ] {
        let mut raw = client
            .sign_request(
                "POST",
                &request(ORIGIN, "POST", "ops", 0).path_and_query,
                vec![b'x'; 65_537],
                None,
            )
            .unwrap()
            .request;
        raw.path_and_query = request(ORIGIN, "POST", suffix, 0).path_and_query;
        assert_eq!(http::body_cap(&raw.method, &raw.path_and_query), None);
        let normalized = reqwest::Url::parse(&raw.url()).unwrap();
        assert_eq!(
            normalized.path(),
            request(ORIGIN, "POST", "inbox", 0).path_and_query
        );
        assert_eq!(http::body_cap(&raw.method, normalized.path()), Some(65_536));
        // The changed target is signed again, so a stale signature cannot explain refusal.
        outcomes.push(client.send(signed(raw)).await);
    }
    assert_eq!(
        resolver.0.load(Ordering::SeqCst),
        0,
        "no connection was attempted"
    );
    for outcome in outcomes {
        assert!(
            matches!(
                outcome,
                Err(ClientError::Transport(TransportError::InvalidRequest(_)))
            ),
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn test_http_raw_send_changed_path_or_query_is_rejected_before_connecting() {
    let (client, resolver) = no_network();
    let mut outcomes = Vec::new();
    for suffix in [
        "ops\\..\\inbox",
        "ops/space here",
        "ops/\u{e9}",
        "ops?value=one two",
        "ops?value=one\ttwo",
        "ops?value=one\r\ntwo",
        "ops?value='x'",
        "ops?value=\u{e9}",
        "ops?value=1#fragment",
        "ops#",
    ] {
        outcomes.push(
            client
                .send(signed(request(ORIGIN, "POST", suffix, 1)))
                .await,
        );
    }
    assert_eq!(
        resolver.0.load(Ordering::SeqCst),
        0,
        "no connection was attempted"
    );
    for outcome in outcomes {
        assert!(
            matches!(
                outcome,
                Err(ClientError::Transport(TransportError::InvalidRequest(_)))
            ),
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn test_http_canonical_target_reaches_the_connector() {
    let (client, resolver) = no_network();
    let outcome = client
        .send(signed(request(ORIGIN, "POST", "inbox", 65_536)))
        .await;
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    assert!(
        matches!(
            outcome,
            Err(ClientError::Transport(TransportError::Connect(_)))
        ),
        "{outcome:?}"
    );
}

/// Read the actual HTTP target, signed headers and body; answer bound to those bytes.
async fn answer_socket(mut socket: tokio::net::TcpStream, origin: String, unread: bool) -> Request {
    let mut bytes = Vec::new();
    let end = loop {
        let mut buffer = [0; 8192];
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let text = std::str::from_utf8(&bytes[..end]).unwrap();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap().split(' ');
    let method = first.next().unwrap().to_owned();
    let path_and_query = first.next().unwrap().to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| {
            line.split_once(": ")
                .map(|(name, value)| Header::new(name, value))
        })
        .collect();
    let length = super::super::header_value(&headers, "content-length")
        .map_or(0, |value| value.parse::<usize>().unwrap());
    if !unread {
        while bytes.len() < end + length {
            let mut buffer = [0; 8192];
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    let received = Request {
        method,
        origin,
        path_and_query,
        headers,
        body: if unread {
            Vec::new()
        } else {
            bytes[end..end + length].to_vec()
        },
        timeout: TimeoutClass::Ordinary,
    };
    if !unread {
        let headers = RequestHeaders {
            timestamp: received.header(header::TIMESTAMP).unwrap().into(),
            identity: received.header(header::IDENTITY).unwrap().into(),
            ..RequestHeaders::default()
        };
        let target = RequestTarget {
            method: &received.method,
            origin: &received.origin,
            path_and_query: &received.path_and_query,
            body: &received.body,
        };
        let signature =
            pubky_switch_core::enc::unb64_array::<64>(received.header(header::SIGNATURE).unwrap())
                .unwrap();
        http::verify_request(
            &IdentityKey::from_secret([1; 32]).public(),
            &target,
            &headers,
            &signature,
        )
        .unwrap();
    }
    let (status, body) = if unread {
        (413, r#"{"code":"too_large","message":"m"}"#)
    } else {
        (200, "{}")
    };
    let time = pubky_switch_core::time::rfc3339(NOW);
    let signature = http::sign_response(
        &IdentityKey::from_secret([5; 32]),
        &ResponseParts {
            status,
            request: SentRequest::of(&received).received(!unread),
            server_time: &time,
            head: None,
            body: body.as_bytes(),
        },
    );
    let answer = format!(
        "HTTP/1.1 {status} Answer\r\nContent-Length: {}\r\nConnection: close\r\nSwitch-Server-Time: {time}\r\nSwitch-Service-Signature: {}\r\n\r\n{body}",
        body.len(),
        b64(&signature)
    );
    socket.write_all(answer.as_bytes()).await.unwrap();
    received
}

async fn loopback_send(
    method: &str,
    suffix: &str,
    bytes: usize,
    unread: bool,
) -> Result<crate::client::CheckedResponse, ClientError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let request = signed(request(&origin, method, suffix, bytes));
    let expected = request.request.clone();
    let server_origin = origin.clone();
    let server = async move {
        let (socket, _) = listener.accept().await.unwrap();
        answer_socket(socket, server_origin, unread).await
    };
    let transport =
        HttpTransport::without_address_checks_for_loopback_tests(HttpConfig::default()).unwrap();
    let client = client(&origin, Arc::new(transport));
    let (outcome, received) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(request), server)
    })
    .await
    .expect("the loopback exchange finishes");
    assert_eq!(received.method, expected.method);
    assert_eq!(received.path_and_query, expected.path_and_query);
    assert_eq!(
        received.header(header::SIGNATURE),
        expected.header(header::SIGNATURE)
    );
    if !unread {
        assert_eq!(received.body, expected.body);
    }
    outcome
}

#[tokio::test]
async fn test_http_raw_send_preserves_canonical_signed_target_and_body() {
    for (method, suffix, bytes) in [
        ("POST", "inbox?z=%2f&a=one+two&z=%2F&empty=", 65_536),
        ("POST", "ops?", 65_537),
        ("POST", "ops?path=../inbox", 1),
        ("POST", "ops/%2f/%C3%A9?x=%23", 1),
        ("GET", "identity", 0),
    ] {
        let answer = loopback_send(method, suffix, bytes, false).await.unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, b"{}");
    }
}

#[tokio::test]
async fn test_http_raw_send_unread_413_remains_nonfinal() {
    let error = loopback_send("POST", "inbox", 65_536, true)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            ClientError::BodyUnread {
                status: 413,
                code: http::ErrorCode::TooLarge,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!((error.code(), error.retry()), (None, None));
}
