use anyhow::Result;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

pub fn setup() -> Result<()> {
    let use_json = false; // TODO

    let filter_layer = EnvFilter::from_env("SEALPROXY_LOG");

    if use_json {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt::layer())
            .init();
    }

    Ok(())
}
