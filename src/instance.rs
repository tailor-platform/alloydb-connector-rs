use crate::error::Error;

#[derive(Debug, Clone)]
pub struct InstanceUri {
    pub project: String,
    pub location: String,
    pub cluster: String,
    pub instance: String,
}

impl InstanceUri {
    pub fn parse(uri: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = uri.split('/').collect();

        if parts.len() != 8 {
            return Err(Error::InvalidInstanceUri(format!(
                "expected format: projects/{{project}}/locations/{{location}}/clusters/{{cluster}}/instances/{{instance}}, got: {uri}"
            )));
        }

        if parts[0] != "projects"
            || parts[2] != "locations"
            || parts[4] != "clusters"
            || parts[6] != "instances"
        {
            return Err(Error::InvalidInstanceUri(format!(
                "invalid URI structure: {uri}"
            )));
        }

        let project = parts[1];
        let location = parts[3];
        let cluster = parts[5];
        let instance = parts[7];

        if project.is_empty() || location.is_empty() || cluster.is_empty() || instance.is_empty() {
            return Err(Error::InvalidInstanceUri(
                "project, location, cluster, and instance cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            project: project.to_string(),
            location: location.to_string(),
            cluster: cluster.to_string(),
            instance: instance.to_string(),
        })
    }

    pub fn instance_path(&self) -> String {
        format!(
            "projects/{}/locations/{}/clusters/{}/instances/{}",
            self.project, self.location, self.cluster, self.instance
        )
    }

    pub fn cluster_path(&self) -> String {
        format!(
            "projects/{}/locations/{}/clusters/{}",
            self.project, self.location, self.cluster
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_instance_uri() {
        let uri = "projects/my-project/locations/us-central1/clusters/my-cluster/instances/primary";
        let parsed = InstanceUri::parse(uri).unwrap();

        assert_eq!(parsed.project, "my-project");
        assert_eq!(parsed.location, "us-central1");
        assert_eq!(parsed.cluster, "my-cluster");
        assert_eq!(parsed.instance, "primary");
    }

    #[test]
    fn test_parse_invalid_format() {
        let uri = "invalid-format";
        assert!(InstanceUri::parse(uri).is_err());
    }

    #[test]
    fn test_parse_wrong_structure() {
        let uri = "project/my-project/location/us-central1/cluster/my-cluster/instance/primary";
        assert!(InstanceUri::parse(uri).is_err());
    }

    #[test]
    fn test_parse_empty_parts() {
        let uri = "projects//locations/us-central1/clusters/my-cluster/instances/primary";
        assert!(InstanceUri::parse(uri).is_err());
    }

    #[test]
    fn test_instance_path() {
        let uri = "projects/my-project/locations/us-central1/clusters/my-cluster/instances/primary";
        let parsed = InstanceUri::parse(uri).unwrap();
        assert_eq!(
            parsed.instance_path(),
            "projects/my-project/locations/us-central1/clusters/my-cluster/instances/primary"
        );
    }

    #[test]
    fn test_cluster_path() {
        let uri = "projects/my-project/locations/us-central1/clusters/my-cluster/instances/primary";
        let parsed = InstanceUri::parse(uri).unwrap();
        assert_eq!(
            parsed.cluster_path(),
            "projects/my-project/locations/us-central1/clusters/my-cluster"
        );
    }
}
