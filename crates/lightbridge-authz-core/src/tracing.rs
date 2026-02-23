use crate::config::Config;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::OnceLock;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

static OTEL_TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

pub trait TracingConfig {
    fn logging_level(&self) -> &str;
    fn otel_enabled(&self) -> bool;
    fn otlp_endpoint(&self) -> &str;
    fn service_name(&self) -> &str;
}

impl TracingConfig for Config {
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

pub fn init_tracing(config: &Config) {
    init_tracing_from(config)
}

pub fn init_tracing_from<T: TracingConfig>(config: &T) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.logging_level()));

    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = Registry::default().with(env_filter).with(fmt_layer);

    if config.otel_enabled() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.otlp_endpoint())
            .build()
            .expect("Failed to build OTLP exporter");

        let resource = Resource::builder()
            .with_service_name(config.service_name().to_string())
            .build();

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        let _ = OTEL_TRACER_PROVIDER.set(tracer_provider.clone());
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());

        let tracer = tracer_provider.tracer(config.service_name().to_string());
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        registry.with(otel_layer).init();
    } else {
        registry.init();
    }
}

pub fn shutdown_tracing() {
    if let Some(provider) = OTEL_TRACER_PROVIDER.get() {
        let _ = provider.force_flush();
        let _ = provider.shutdown();
    }
}
