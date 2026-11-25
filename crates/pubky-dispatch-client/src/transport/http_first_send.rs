//! An individual HTTP/1 connection for a request with a first-handoff cutoff. The
//! socket checks its admission on each write, including after DNS, TLS and backpressure.
//! Once bytes leave the socket, their arrival and application are up to the service.

use super::*;
use crate::transport::FirstSend;
use http_body_util::Full;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls};

struct Socket<'a> {
    stream: TcpStream,
    first: &'a FirstSend,
}

impl AsyncRead for Socket<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, read)
    }
}

impl AsyncWrite for Socket<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.stream.poll_write_ready(cx))?;
            self.first.check().map_err(io::Error::other)?;
            match self.stream.try_write(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl HttpTransport {
    pub(super) fn first_send_tls(
        roots: rustls::RootCertStore,
    ) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Other(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Arc::new(config))
    }

    pub(super) async fn send_connected(
        &self,
        native: reqwest::Request,
        first: &FirstSend,
        method: &str,
        path: &str,
    ) -> Result<Response, TransportError> {
        let url = native.url();
        let host = url
            .host()
            .ok_or_else(|| TransportError::InvalidRequest("missing host".into()))?
            .to_string();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TransportError::InvalidRequest("missing port".into()))?;
        let stream = tokio::time::timeout(self.connect_timeout, async {
            let addrs: Vec<_> = tokio::net::lookup_host((host, port))
                .await
                .map_err(connect_error)?
                .collect();
            if self.origin_use.is_some() {
                let ips: Vec<_> = addrs.iter().map(SocketAddr::ip).collect();
                check_addresses(&ips).map_err(|e| TransportError::Refused(e.to_string()))?;
            }
            TcpStream::connect(addrs.as_slice())
                .await
                .map_err(connect_error)
        })
        .await
        .map_err(|_| TransportError::Timeout)??;
        let stream = Socket { stream, first };
        if url.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| TransportError::InvalidRequest("invalid TLS server name".into()))?;
            let tls = tokio::time::timeout(
                self.connect_timeout,
                TlsConnector::from(Arc::clone(&self.first_send_tls)).connect(name, stream),
            )
            .await
            .map_err(|_| TransportError::Timeout)?
            // HTTP has not received the request. An expired handshake can therefore
            // report the request as unsent even if TLS wrote its greeting.
            .map_err(|error| first.check().err().unwrap_or_else(|| connect_error(error)))?;
            first.check()?;
            self.exchange(tls, native, method, path).await
        } else if self.origin_use.is_none() && url.scheme() == "http" {
            self.exchange(stream, native, method, path).await
        } else {
            Err(TransportError::Refused("the origin must use HTTPS".into()))
        }
    }

    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        native: reqwest::Request,
        method: &str,
        path: &str,
    ) -> Result<Response, TransportError> {
        let host = &native.url()[url::Position::BeforeHost..url::Position::AfterPort];
        let mut builder = hyper::Request::builder()
            .method(native.method())
            .uri(path)
            .header("host", host)
            .header("connection", "close");
        for (name, value) in native.headers() {
            builder = builder.header(name, value);
        }
        let body = native
            .body()
            .and_then(reqwest::Body::as_bytes)
            .ok_or_else(|| TransportError::InvalidRequest("missing operation body".into()))?;
        let request = builder
            .body(Full::new(bytes::Bytes::copy_from_slice(body)))
            .map_err(|_| TransportError::InvalidRequest("invalid request".into()))?;
        let (mut send, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(exchange_error)?;
        let receive = async {
            let response = send.send_request(request).await.map_err(exchange_error)?;
            drop(send);
            self.read_response(
                reqwest::Response::from(response.map(reqwest::Body::wrap)),
                method,
                path,
            )
            .await
        };
        tokio::pin!(receive);
        tokio::select! {
            answer = &mut receive => answer,
            _ = connection => receive.await,
        }
    }
}

fn connect_error(error: io::Error) -> TransportError {
    TransportError::Connect(error.to_string())
}

// A partial write or a lost response cannot establish that no byte left this connection.
fn exchange_error(error: hyper::Error) -> TransportError {
    TransportError::Other(error.to_string())
}
