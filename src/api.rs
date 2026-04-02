use crate::config::IpType;
use crate::error::Error;
use crate::instance::InstanceUri;
use crate::retry::{log_retry, should_retry_response};
use chrono::{DateTime, TimeZone, Utc};
use gcp_auth::TokenProvider;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use x509_parser::pem::parse_x509_pem;

const DEFAULT_API_ENDPOINT: &str = "https://alloydb.googleapis.com";
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfoResponse {
    pub ip_address: Option<String>,
    pub public_ip_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateClientCertificateRequest {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_metadata_exchange: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateClientCertificateResponse {
    pub pem_certificate_chain: Vec<String>,
    pub ca_cert: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ca_cert: String,
    pub client_cert_chain: Vec<String>,
    pub ip_address: IpAddr,
    pub expires_at: DateTime<Utc>,
}

pub struct AlloyDbApiClient {
    http_client: Client,
    provider: Arc<dyn TokenProvider>,
    api_endpoint: String,
}

impl AlloyDbApiClient {
    pub async fn new(api_endpoint: Option<String>) -> Result<Self, Error> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        let http_client = Client::builder()
            .build()
            .map_err(|e| Error::ApiRequestFailed(e.to_string()))?;

        Ok(Self {
            http_client,
            provider,
            api_endpoint: api_endpoint.unwrap_or_else(|| DEFAULT_API_ENDPOINT.to_string()),
        })
    }

    async fn get_auth_header(&self) -> Result<String, Error> {
        let token = self
            .provider
            .token(&[CLOUD_PLATFORM_SCOPE])
            .await
            .map_err(|e| Error::AuthenticationFailed(e.to_string()))?;

        Ok(format!("Bearer {}", token.as_str()))
    }

    pub async fn get_connection_info(
        &self,
        instance: &InstanceUri,
    ) -> Result<ConnectionInfoResponse, Error> {
        let url = format!(
            "{}/v1/{}/connectionInfo",
            self.api_endpoint,
            instance.instance_path()
        );

        let mut attempt = 0u32;
        loop {
            let auth_header = self.get_auth_header().await?;

            let response = self
                .http_client
                .get(&url)
                .header("Authorization", auth_header.clone())
                .send()
                .await?;

            if response.status().is_success() {
                return response
                    .json::<ConnectionInfoResponse>()
                    .await
                    .map_err(|e| Error::ApiRequestFailed(e.to_string()));
            }

            let status = response.status();
            let retry_result = should_retry_response(&response, attempt);

            if let Some(wait) = retry_result.wait_duration {
                log_retry(attempt, status, wait, retry_result.is_rate_limit);
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(Error::ApiRequestFailed(format!(
                "GET {url} failed with status {status}: {body}"
            )));
        }
    }

    pub async fn generate_client_certificate(
        &self,
        instance: &InstanceUri,
        public_key_pem: &str,
    ) -> Result<GenerateClientCertificateResponse, Error> {
        let url = format!(
            "{}/v1/{}:generateClientCertificate",
            self.api_endpoint,
            instance.cluster_path()
        );

        let request_body = GenerateClientCertificateRequest {
            public_key: public_key_pem.to_string(),
            cert_duration: Some("3600s".to_string()),
            use_metadata_exchange: Some(false),
        };

        let mut attempt = 0u32;
        loop {
            let auth_header = self.get_auth_header().await?;

            let response = self
                .http_client
                .post(&url)
                .header("Authorization", auth_header.clone())
                .json(&request_body)
                .send()
                .await?;

            if response.status().is_success() {
                return response
                    .json::<GenerateClientCertificateResponse>()
                    .await
                    .map_err(|e| Error::ApiRequestFailed(e.to_string()));
            }

            let status = response.status();
            let retry_result = should_retry_response(&response, attempt);

            if let Some(wait) = retry_result.wait_duration {
                log_retry(attempt, status, wait, retry_result.is_rate_limit);
                tokio::time::sleep(wait).await;
                attempt += 1;
                continue;
            }

            let body = response.text().await.unwrap_or_default();
            return Err(Error::ApiRequestFailed(format!(
                "POST {url} failed with status {status}: {body}"
            )));
        }
    }

    pub async fn fetch_connection_info(
        &self,
        instance: &InstanceUri,
        ip_type: &IpType,
        public_key_pem: &str,
    ) -> Result<ConnectionInfo, Error> {
        let conn_info = self.get_connection_info(instance).await?;
        let cert_response = self
            .generate_client_certificate(instance, public_key_pem)
            .await?;

        let ip_address_str = match ip_type {
            IpType::Private => conn_info
                .ip_address
                .ok_or_else(|| Error::ConnectionFailed("no private IP address".to_string()))?,
            IpType::Public => conn_info
                .public_ip_address
                .ok_or_else(|| Error::ConnectionFailed("no public IP address".to_string()))?,
            IpType::Psc => {
                return Err(Error::ConnectionFailed(
                    "PSC DNS name requires different connection method".to_string(),
                ));
            }
        };

        let ip_address: IpAddr = ip_address_str
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("invalid IP address: {e}")))?;

        // Parse the client certificate (first in chain) to extract expiration from X.509 NotAfter
        // This matches the Go connector's approach of reading from the cert itself
        let client_cert = cert_response
            .pem_certificate_chain
            .first()
            .ok_or_else(|| Error::CertificateError("empty certificate chain".to_string()))?;
        let expires_at = parse_cert_expiration(client_cert)?;

        Ok(ConnectionInfo {
            ca_cert: cert_response.ca_cert,
            client_cert_chain: cert_response.pem_certificate_chain,
            ip_address,
            expires_at,
        })
    }
}

/// Parse a PEM-encoded X.509 certificate and extract the NotAfter expiration time.
fn parse_cert_expiration(pem_cert: &str) -> Result<DateTime<Utc>, Error> {
    let (_, pem) = parse_x509_pem(pem_cert.as_bytes())
        .map_err(|e| Error::CertificateError(format!("failed to parse PEM: {e}")))?;

    let cert = pem
        .parse_x509()
        .map_err(|e| Error::CertificateError(format!("failed to parse X.509 certificate: {e}")))?;

    let not_after = cert.validity().not_after;
    let timestamp = not_after.timestamp();

    Utc.timestamp_opt(timestamp, 0)
        .single()
        .ok_or_else(|| Error::CertificateError("invalid certificate expiration timestamp".into()))
}

pub async fn fetch_connection_info(
    api_endpoint: &Option<String>,
    instance: &InstanceUri,
    ip_type: &IpType,
    public_key_pem: &str,
) -> Result<ConnectionInfo, Error> {
    let api_client = AlloyDbApiClient::new(api_endpoint.clone()).await?;
    api_client
        .fetch_connection_info(instance, ip_type, public_key_pem)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test certificate generated with:
    // openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 365 -nodes -subj "/CN=test"
    // Expires: Jan 12 2027
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUMwFTEMgvtcN2YhIFDB4+FYAqMuowDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMTIwMTMwNDVaFw0yNzAxMTIwMTMw
NDVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC4eRxMjczvdZlCDntwB1yfbArym81GLwsI4GlS2pWPNEk9YOYq3KxlPfD2
kokxLaDItPtv5jVctqcLbvIP57ZrlRi1rWRNmYJYRmPmcYFDAgnKiAP7fTgIAt0F
y+XQMN5a6N/NvFrcAA+weikcZUEzamk3vunBd0v5z7SMkhZ1+TXIQsP31j2HGpBb
ceqV2uRo9Y1aNJmwmlNNCPJ+r6/cFnJQOkPKzfc3ddQXjw1OSL5DUc4cWH7ViUCy
CapG/WP3iN34CC13zKd5/UFDkPnX4z6yL2vzLpB9j06+NFmc004As5HAZiTIJ3QC
Cq0ekwQ1+qAzNQARgbQlEoHJnHi1AgMBAAGjUzBRMB0GA1UdDgQWBBR+fn/Lzszg
uED9llsd1QNxbId8GTAfBgNVHSMEGDAWgBR+fn/LzszguED9llsd1QNxbId8GTAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAA32Oai+cJO1k1dtNw
TgEldVaj4LrJ+WDrdtriCOGlmC7yOVcY9n9EoyTGqEzxPt2MZCD+bLF9jamvpnTA
Je4i+9boVkoAmYcjD1TAtDzxnmWbdwh/L4XncLaVp9WtpDoA+GGOdFM8m0PJjK0W
3Jr2wzwE7vuQhmMF1M0JFZXSaSmSgBHbHNvTDPym/vguHqHdtkxJXLoGzXz43NU+
GjWOWr//DUPmErqvfyn6r0MmaEeCc/m4kzOZ3jQZs/fPAdO9e00mx3q9aBW/+FYG
4wNkCkHF4CPuSGUDkmEG0UyFq9MIPbH1qIHjmpgGeOJMbQGFkiL67D4guJKSb3bC
96sr
-----END CERTIFICATE-----"#;

    #[test]
    fn test_parse_cert_expiration_valid() {
        let result = parse_cert_expiration(TEST_CERT_PEM);
        assert!(result.is_ok(), "should parse valid certificate");
        let expires_at = result.unwrap();
        // Verify the year is 2027 (the NotAfter year in the test cert)
        assert_eq!(expires_at.format("%Y").to_string(), "2027");
    }

    #[test]
    fn test_parse_cert_expiration_invalid_pem() {
        let result = parse_cert_expiration("not a valid PEM");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::CertificateError(_)));
    }

    #[test]
    fn test_parse_cert_expiration_empty() {
        let result = parse_cert_expiration("");
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_info_response_deserialization() {
        let json = r#"{
            "ipAddress": "10.0.0.1",
            "publicIpAddress": "35.1.2.3"
        }"#;

        let info: ConnectionInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(info.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(info.public_ip_address, Some("35.1.2.3".to_string()));
    }

    #[test]
    fn test_connection_info_response_private_only() {
        let json = r#"{
            "ipAddress": "10.0.0.1"
        }"#;

        let info: ConnectionInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(info.ip_address, Some("10.0.0.1".to_string()));
        assert!(info.public_ip_address.is_none());
    }

    #[test]
    fn test_generate_client_certificate_response_deserialization() {
        let json = r#"{
            "pemCertificateChain": ["-----BEGIN CERTIFICATE-----\ncert1\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\ncert2\n-----END CERTIFICATE-----"],
            "caCert": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----"
        }"#;

        let response: GenerateClientCertificateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.pem_certificate_chain.len(), 2);
        assert!(response.ca_cert.contains("BEGIN CERTIFICATE"));
    }
}
