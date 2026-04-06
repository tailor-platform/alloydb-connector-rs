# alloydb-connector

A Rust connector for [Google Cloud AlloyDB](https://cloud.google.com/alloydb). Provides secure, authenticated connections to AlloyDB instances using IAM authentication and automatic certificate management.

## Features

- Automatic TLS certificate management with background refresh
- IAM-based authentication
- Connection pooling via [deadpool](https://crates.io/crates/deadpool)
- Support for both public and private IP connections

## Usage

```rust
use alloydbconn::{AlloyDbConfig, AlloyDbConnector};

let config = AlloyDbConfig::new("projects/my-project/locations/us-central1/clusters/my-cluster/instances/my-instance")
    .with_iam_auth(true);

let connector = AlloyDbConnector::new(config).await?;
let pool = connector.create_pool("my_database", "my_user", None)?;
let conn = pool.get().await?;
```

## License

MIT
