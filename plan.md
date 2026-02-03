## Plan

1. Audit current crates/config for REST/gRPC wiring and TLS.
2. Redesign data model and migrations for accounts, projects, and API keys.
3. Implement CRUD HTTP API for keys/projects/orgs and key lifecycle features.
4. Add second HTTP server for Authorino OPA with basic auth and TLS.
5. Remove gRPC surfaces and update CLI/config/docs accordingly.
