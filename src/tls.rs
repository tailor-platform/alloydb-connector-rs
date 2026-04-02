use crate::cert::CachedCertificate;
use crate::error::Error;
use arc_swap::ArcSwap;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[derive(Clone)]
pub struct AlloyDbTlsConnector {
    cache: Arc<ArcSwap<CachedCertificate>>,
}

impl AlloyDbTlsConnector {
    pub(crate) fn from_cache(cache: Arc<ArcSwap<CachedCertificate>>) -> Self {
        Self { cache }
    }
}

/// Builds a TLS configuration from a cached certificate.
///
/// Unlike Cloud SQL (which uses "project:instance" format in CN/SAN requiring custom
/// verification), AlloyDB certificates have standard IP addresses in SANs. This allows
/// us to use standard rustls verification with ServerName::IpAddress.
pub(crate) fn build_tls_config_from_cert(cert: &CachedCertificate) -> Result<ClientConfig, Error> {
    let mut root_store = RootCertStore::empty();
    for ca_cert in &cert.server_ca_certs {
        root_store
            .add(ca_cert.clone())
            .map_err(|e| Error::TlsConfigurationFailed(format!("failed to add CA cert: {e}")))?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert.client_certs.clone(), cert.client_key.clone_key())
        .map_err(|e| Error::TlsConfigurationFailed(format!("failed to set client cert: {e}")))?;

    Ok(config)
}

impl<S> MakeTlsConnect<S> for AlloyDbTlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = AlloyDbTlsStream<S>;
    type TlsConnect = AlloyDbTlsConnect;
    type Error = Error;

    fn make_tls_connect(&mut self, _host: &str) -> Result<Self::TlsConnect, Self::Error> {
        let cert = self.cache.load();
        let config = build_tls_config_from_cert(&cert)?;
        Ok(AlloyDbTlsConnect {
            connector: TlsConnector::from(Arc::new(config)),
            ip_address: cert.ip_address,
        })
    }
}

pub struct AlloyDbTlsConnect {
    connector: TlsConnector,
    ip_address: IpAddr,
}

impl<S> TlsConnect<S> for AlloyDbTlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = AlloyDbTlsStream<S>;
    type Error = Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            // Use IP address as ServerName for proper certificate verification.
            // AlloyDB certificates have IP addresses in SANs.
            let server_name = ServerName::IpAddress(self.ip_address.into());

            let tls_stream = self
                .connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

            Ok(AlloyDbTlsStream { inner: tls_stream })
        })
    }
}

pub struct AlloyDbTlsStream<S> {
    inner: TlsStream<S>,
}

impl<S> AsyncRead for AlloyDbTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for AlloyDbTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> tokio_postgres::tls::TlsStream for AlloyDbTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}
