#!/usr/bin/env python3
"""Seed usage_events with realistic multi-day, multi-project data.

Drives the real OTLP ingest endpoint (POST /v1/otel/traces) so seeding exercises
the true extraction + validation + insert write path, per lightbridge-authz#528.

Usage:
    python3 scripts/seed-usage-events.py [--ingest-url URL] [--db-url URL] [--days N]
                                       [--i-understand-this-truncates]

Defaults:
    --ingest-url  https://localhost:13002
    --db-url      postgres://postgres:postgres@localhost:5433/lightbridge_authz_usage
    --days        14

The script truncates usage_events first (idempotency: re-running never doubles
figures), then generates and POSTs OTLP trace payloads. TRUNCATE is irrecoverable,
so the script refuses to truncate anything that is not provably the local compose
database (localhost/127.0.0.1/::1) unless --i-understand-this-truncates is passed.

Costs are in micro-USD (the gateway's `llm_custom_total_cost` unit -- see
`crates/lightbridge-authz-budget/src/spend_units.rs`, #488). Token counts are in
the hundreds-to-thousands range. Latency is in milliseconds. These magnitudes
match production semantics -- the historical 10^6 cost error was treating
micro-USD as dollars, and seeding dollars would render as 10^-6 dollars on the
console, which divides by 1e6 for display.
"""

import argparse
import json
import random
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# Dimension catalogue. Each project belongs to an account; each user belongs to
# an account; each api key belongs to a project.
ACCOUNTS = ["acct_001", "acct_002"]
PROJECTS = [
    ("proj_001", "acct_001"),
    ("proj_002", "acct_002"),
    ("proj_003", "acct_002"),
]
USERS = [
    ("user_alice", "Alice"),
    ("user_bob", "Bob"),
]
API_KEYS = ["key_001", "key_002"]
MODELS = [
    "gpt-4.1",
    "gpt-4.1-mini",
    "claude-sonnet-4",
    "gemini-2.5-pro",
    "o3",
]
METRIC_NAMES = ["chat.completion", "embeddings", "chat.completion.stream"]

# Per-model pricing in dollars per 1K tokens (input, output). Used to compute a
# realistic total_cost per event. These are approximate list prices.
MODEL_PRICING = {
    "gpt-4.1": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "claude-sonnet-4": (3.00, 15.00),
    "gemini-2.5-pro": (1.25, 10.00),
    "o3": (2.00, 8.00),
}

# Events per hour per project. Keeps the total row count modest (~1.5k for 14
# days across 3 projects) while still giving every bucket interval data.
EVENTS_PER_HOUR_PER_PROJECT = 5


def _is_local_host(host: str | None) -> bool:
    """True for the loopback hostnames the compose stack binds."""
    return host in ("localhost", "127.0.0.1", "::1")


def _resolve_host(db_url: str) -> str | None:
    """Extract the host from a libpq URL, or None when it cannot be parsed.

    None means "not provably local" -- the caller must fail closed.
    """
    parsed = urllib.parse.urlparse(db_url)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return None


def truncate_usage_events(db_url: str, allow_non_local: bool) -> None:
    """Truncate usage_events so re-running never doubles figures.

    TRUNCATE is irrecoverable, so refuse to run against anything that is not
    provably the local compose database unless --i-understand-this-truncates
    was passed. A DSN that cannot be parsed as a URL is treated as non-local
    (fail closed).
    """
    try:
        import psycopg2
    except ImportError:
        print(
            "error: psycopg2 is required to truncate usage_events. "
            "Install it with: pip install psycopg2-binary",
            file=sys.stderr,
        )
        sys.exit(1)
    host = _resolve_host(db_url)
    if not allow_non_local and not _is_local_host(host):
        print(
            "error: refusing to TRUNCATE usage_events on a non-local database "
            f"(resolved host: {host!r}). The seed truncates its target before "
            "writing; pointing it at a shared or staging database would destroy "
            "real rows. Pass --i-understand-this-truncates to override.",
            file=sys.stderr,
        )
        sys.exit(1)
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE usage_events")
        conn.commit()
        print(f"truncated usage_events on {host}")
    finally:
        conn.close()


def make_span(
    observed_at: datetime,
    account_id: str,
    project_id: str,
    api_key_id: str,
    user_id: str,
    user_name: str,
    model: str,
    metric_name: str,
    span_index: int,
) -> dict:
    """Build one OTLP Span dict in the protobuf-JSON shape the handler decodes."""
    prompt = random.randint(100, 4000)
    completion = random.randint(50, 3000)
    total = prompt + completion
    input_price, output_price = MODEL_PRICING[model]
    # Cost in micro-USD: dollars-per-1K pricing x tokens, then x 1e6. The gateway's
    # llm_custom_total_cost CEL emits micro-USD and ingest stores it verbatim
    # (spend_units.rs, #488) -- seeding dollars would be the historical 10^6 error.
    cost = round(((prompt / 1000.0) * input_price + (completion / 1000.0) * output_price) * 1_000_000)
    latency_ms = round(random.uniform(50.0, 5000.0), 2)

    start_nanos = int(observed_at.timestamp() * 1_000_000_000)
    end_nanos = start_nanos + int(latency_ms * 1_000_000)

    return {
        "traceId": f"{span_index:032x}",
        "spanId": f"{span_index:016x}",
        "name": metric_name,
        "startTimeUnixNano": str(start_nanos),
        "endTimeUnixNano": str(end_nanos),
        "attributes": [
            {"key": "account_id", "value": {"stringValue": account_id}},
            {"key": "project_id", "value": {"stringValue": project_id}},
            {"key": "api_key_id", "value": {"stringValue": api_key_id}},
            {"key": "lc_user_id", "value": {"stringValue": user_id}},
            {"key": "lc_user_name", "value": {"stringValue": user_name}},
            {"key": "model", "value": {"stringValue": model}},
            {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": str(prompt)}},
            {"key": "gen_ai.usage.completion_tokens", "value": {"intValue": str(completion)}},
            {"key": "gen_ai.usage.total_tokens", "value": {"intValue": str(total)}},
            {"key": "io.envoy.ai_gateway.llm_custom_total_cost", "value": {"doubleValue": cost}},
            {"key": "gen_ai.server.request.duration", "value": {"doubleValue": latency_ms / 1000.0}},
        ],
    }


def build_payload(spans: list[dict]) -> dict:
    """Wrap a list of spans into an ExportTraceServiceRequest JSON body."""
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "ai-gateway"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "seed", "version": "1.0"},
                        "spans": spans,
                    }
                ],
            }
        ]
    }


def post_payload(ingest_url: str, payload: dict) -> None:
    """POST one OTLP trace payload to the ingest endpoint."""
    body = json.dumps(payload).encode("utf-8")
    url = f"{ingest_url.rstrip('/')}/v1/otel/traces"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            if resp.status != 202:
                raise RuntimeError(f"ingest returned {resp.status}: {resp.read().decode()}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"ingest returned {e.code}: {e.read().decode()}") from e


def generate_events(days: int, now: datetime) -> list[dict]:
    """Generate OTLP spans across the requested window."""
    spans = []
    span_index = 0
    start = now - timedelta(days=days)
    # Walk hour by hour so every bucket interval (seconds/minutes/hours/days)
    # has data.
    cursor = start.replace(minute=0, second=0, microsecond=0)
    while cursor < now:
        for project_id, account_id in PROJECTS:
            for _ in range(EVENTS_PER_HOUR_PER_PROJECT):
                # Jitter within the hour so minute/second buckets see spread.
                observed = cursor + timedelta(
                    seconds=random.randint(0, 3599),
                    microseconds=random.randint(0, 999_999),
                )
                user_id, user_name = random.choice(USERS)
                api_key_id = random.choice(API_KEYS)
                model = random.choice(MODELS)
                metric_name = random.choice(METRIC_NAMES)
                spans.append(
                    make_span(
                        observed,
                        account_id,
                        project_id,
                        api_key_id,
                        user_id,
                        user_name,
                        model,
                        metric_name,
                        span_index,
                    )
                )
                span_index += 1
        cursor += timedelta(hours=1)
    return spans


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ingest-url", default="https://localhost:13002")
    parser.add_argument(
        "--db-url",
        default="postgres://postgres:postgres@localhost:5433/lightbridge_authz_usage",
    )
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument(
        "--i-understand-this-truncates",
        action="store_true",
        help="allow TRUNCATE against a non-local --db-url host",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    truncate_usage_events(args.db_url, args.i_understand_this_truncates)

    spans = generate_events(args.days, now)
    print(f"generated {len(spans)} spans across {args.days} days")

    # POST in batches of 500 to keep each request modest.
    batch_size = 500
    accepted = 0
    for i in range(0, len(spans), batch_size):
        batch = spans[i : i + batch_size]
        post_payload(args.ingest_url, build_payload(batch))
        accepted += len(batch)
        print(f"  posted {len(batch)} spans ({accepted}/{len(spans)})")

    print(f"done: {accepted} events seeded")


if __name__ == "__main__":
    main()
