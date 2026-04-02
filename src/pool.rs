use crate::AlloyDbConnector;
use crate::error::Error;
use deadpool::managed::{Manager, Metrics, RecycleError, RecycleResult};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_postgres::Client;
use tokio_rustls::TlsConnector;

/// The port that AlloyDB's server-side proxy receives connections on.
/// This is fixed and not configurable - all AlloyDB instances accept
/// mTLS connections on this port.
const SERVER_PROXY_PORT: u16 = 5433;

pub type AlloyDbPool = deadpool::managed::Pool<AlloyDbPoolManager>;

pub struct PooledConnection {
    pub client: Client,
    created_at: Instant,
}

impl PooledConnection {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            created_at: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

pub struct AlloyDbPoolManager {
    connector: Arc<AlloyDbConnector>,
    dbname: String,
    user: String,
    password: Option<String>,
    use_iam_auth: bool,
    max_lifetime: Option<Duration>,
}

impl AlloyDbPoolManager {
    pub fn new(
        connector: Arc<AlloyDbConnector>,
        dbname: String,
        user: String,
        password: Option<String>,
        use_iam_auth: bool,
        max_lifetime: Option<Duration>,
    ) -> Self {
        Self {
            connector,
            dbname,
            user,
            password,
            use_iam_auth,
            max_lifetime,
        }
    }
}

impl Manager for AlloyDbPoolManager {
    type Type = PooledConnection;
    type Error = Error;

    async fn create(&self) -> Result<PooledConnection, Error> {
        let password = if self.use_iam_auth {
            // IAM auth: fetch fresh token for each new connection
            self.connector.get_iam_token().await?.ok_or_else(|| {
                Error::ConnectionFailed("IAM auth enabled but token fetch failed".to_string())
            })?
        } else {
            // Static auth: use configured password
            self.password
                .clone()
                .ok_or_else(|| Error::ConnectionFailed("no password configured".to_string()))?
        };

        let host = self.connector.host();

        // Step 1: Establish TCP connection
        let addr = format!("{host}:{SERVER_PROXY_PORT}");
        let tcp_stream = TcpStream::connect(&addr).await.map_err(|e| {
            Error::ConnectionFailed(format!("TCP connection to {addr} failed: {e}"))
        })?;

        // Step 2: Perform TLS handshake directly (not PostgreSQL SSL negotiation)
        // AlloyDB's server-side proxy expects TLS-first, not PostgreSQL-style SSL upgrade
        let tls_config = self.connector.build_tls_config()?;
        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // Use IP address as ServerName (matching Go connector behavior).
        // AlloyDB certificates have IP addresses in SANs, and our custom verifier
        // validates the IP SAN matches the expected address.
        let server_name = ServerName::IpAddress(host.into());

        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

        // Step 3: Connect PostgreSQL over the already-TLS stream (no SSL negotiation)
        let mut pg_config = tokio_postgres::Config::new();
        pg_config
            .user(&self.user)
            .password(&password)
            .dbname(&self.dbname);

        // Use NoTls since the stream is already TLS-encrypted
        let (client, connection) = pg_config
            .connect_raw(tls_stream, tokio_postgres::NoTls)
            .await
            .map_err(|e| {
                let mut msg = format!("PostgreSQL connection failed: {e}");
                if let Some(code) = e.code() {
                    msg.push_str(&format!(" [SQLSTATE: {}]", code.code()));
                }
                if let Some(source) = e.into_source() {
                    msg.push_str(&format!(" (source: {source})"));
                }
                Error::ConnectionFailed(msg)
            })?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!(error = %e, "PostgreSQL connection task ended with error");
            }
        });

        Ok(PooledConnection::new(client))
    }

    async fn recycle(
        &self,
        conn: &mut PooledConnection,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        // Check max lifetime - reject connections that are too old
        if let Some(max_lifetime) = self.max_lifetime
            && conn.age() > max_lifetime
        {
            return Err(RecycleError::message(format!(
                "connection exceeded max lifetime ({:?})",
                max_lifetime
            )));
        }

        if conn.client.is_closed() {
            return Err(RecycleError::message("connection is closed"));
        }

        conn.client
            .simple_query("")
            .await
            .map_err(|e| RecycleError::message(format!("connection health check failed: {e}")))?;

        Ok(())
    }
}
