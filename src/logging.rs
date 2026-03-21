use anyhow::Result;
use chrono::SecondsFormat;
use colored::Colorize;
use std::fmt::{Debug, Result as FmtResult, Write};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::{EnvFilter, prelude::*};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt};



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
