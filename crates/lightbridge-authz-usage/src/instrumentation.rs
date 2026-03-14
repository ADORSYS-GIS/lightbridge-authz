use crate::config::UsageConfig;
use lightbridge_authz_core::tracing::TracingConfig;
use tracing::info;

impl TracingConfig for UsageConfig {
    fn logging_level(&self) -> &str {
        &self.logging.level
    }

    fn otel_enabled(&self) -> bool {
        self.otel.enabled
    }

    fn otlp_endpoint(&self) -> &str {
        &self.otel.otlp_endpoint
    }

    fn service_name(&self) -> &str {
        &self.otel.service_name
    }
}

pub fn init_tracing(config: &UsageConfig) {
    info!("initializing tracing for usage service");
    lightbridge_authz_core::tracing::init_tracing_from(config);
    info!("tracing initialized successfully");
}

pub fn shutdown_tracing() {
    info!("shutting down tracing for usage service");
    lightbridge_authz_core::tracing::shutdown_tracing();
}
