use std::str::FromStr;
use std::time::Duration;

use crate::error::Error;
use crate::instance::InstanceUri;

/// The type of IP address to use for connecting to AlloyDB.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum IpType {
    /// Connect via private IP (default). Requires VPC connectivity.
    #[default]
    Private,
    /// Connect via public IP. Requires public IP to be enabled on the instance.
    Public,
    /// Connect via Private Service Connect. Note: PSC is not yet supported by this
    /// connector as it requires DNS-based connection rather than IP-based connection.
    /// Using this variant will return an error at connection time.
    Psc,
}

impl FromStr for IpType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "public" => IpType::Public,
            "psc" => IpType::Psc,
            _ => IpType::Private,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AlloyDbConfig {
    pub instance_uri: String,
    pub ip_type: IpType,
    pub refresh_buffer: Duration,
    pub api_endpoint: Option<String>,
    pub use_iam_auth: bool,
}

impl AlloyDbConfig {
    pub fn new(instance_uri: impl Into<String>) -> Result<Self, Error> {
        let instance_uri = instance_uri.into();
        InstanceUri::parse(&instance_uri)?;
        Ok(Self {
            instance_uri,
            ip_type: IpType::default(),
            refresh_buffer: Duration::from_secs(4 * 60),
            api_endpoint: None,
            use_iam_auth: false,
        })
    }

    pub fn with_ip_type(mut self, ip_type: IpType) -> Self {
        self.ip_type = ip_type;
        self
    }

    pub fn with_refresh_buffer(mut self, refresh_buffer: Duration) -> Self {
        self.refresh_buffer = refresh_buffer;
        self
    }

    pub fn with_api_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.api_endpoint = Some(endpoint.into());
        self
    }

    pub fn with_iam_auth(mut self) -> Self {
        self.use_iam_auth = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_type_from_str() {
        assert_eq!("public".parse::<IpType>().unwrap(), IpType::Public);
        assert_eq!("PUBLIC".parse::<IpType>().unwrap(), IpType::Public);
        assert_eq!("psc".parse::<IpType>().unwrap(), IpType::Psc);
        assert_eq!("PSC".parse::<IpType>().unwrap(), IpType::Psc);
        assert_eq!("private".parse::<IpType>().unwrap(), IpType::Private);
        assert_eq!("anything".parse::<IpType>().unwrap(), IpType::Private);
    }

    #[test]
    fn test_config_builder() {
        let config = AlloyDbConfig::new("projects/p/locations/l/clusters/c/instances/i")
            .expect("valid instance uri")
            .with_ip_type(IpType::Public)
            .with_refresh_buffer(Duration::from_secs(300));

        assert_eq!(
            config.instance_uri,
            "projects/p/locations/l/clusters/c/instances/i"
        );
        assert_eq!(config.ip_type, IpType::Public);
        assert_eq!(config.refresh_buffer, Duration::from_secs(300));
    }

    #[test]
    fn test_config_with_api_endpoint() {
        let config = AlloyDbConfig::new("projects/p/locations/l/clusters/c/instances/i")
            .expect("valid instance uri")
            .with_api_endpoint("https://custom.api");

        assert_eq!(config.api_endpoint, Some("https://custom.api".to_string()));
    }

    #[test]
    fn test_config_with_iam_auth() {
        let config = AlloyDbConfig::new("projects/p/locations/l/clusters/c/instances/i")
            .expect("valid instance uri")
            .with_iam_auth();

        assert!(config.use_iam_auth);
    }

    #[test]
    fn test_config_invalid_instance_uri() {
        assert!(AlloyDbConfig::new("invalid-uri").is_err());
        assert!(AlloyDbConfig::new("").is_err());
        assert!(AlloyDbConfig::new("project:region:instance").is_err());
    }
}
