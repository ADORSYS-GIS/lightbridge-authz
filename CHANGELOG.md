# Changelog

## [1.1.0](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v1.0.0...v1.1.0) (2026-07-14)


### Features

* **authz:** account membership management (invite/remove members) ([#123](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/123)) ([11c2dc9](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/11c2dc9ce868a5ac5d20a2f6fc157a9a610053b1))
* **authz:** RBAC — translate Keycloak roles into permissions ([#122](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/122)) ([f3fe824](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/f3fe824259b350b2dd1d15d3ef4d95766cb85748))


### Code Refactoring

* consolidate runtime wrapper packages ([bcac6df](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/bcac6dfbe9f2160bb27bb3e60ce397bf5cf96a6a))
* move mcp adapter into authz package ([30afbb0](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/30afbb0cc9c837b6765b7b2a0ef5b6ac3873552b))
* move mcp adapter into authz package ([997e47b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/997e47b95af00868e930c94895587a9a7ef65142))

## [1.0.0](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v0.8.1...v1.0.0) (2026-07-12)


### ⚠ BREAKING CHANGES

* **oauth2:** required oauth2.type enum (self|external) replaces enabled flags ([#114](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/114))

### Features

* **oauth2:** required oauth2.type enum (self|external) replaces enabled flags ([#114](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/114)) ([2eb840e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/2eb840ea2091c2cae9156ad4be6b9534391c3299))


### Continuous Integration

* **release:** auto-version release PRs via release-please ([#109](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/109)) ([6d6a264](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/6d6a264320d10d76b146e5ee49e23e939af512cb))


### Documentation

* map architecture and propose workspace consolidation ([0d10042](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/0d10042cf53f1048c303b7b0fc2adb8bf1f2129a))
