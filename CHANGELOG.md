# Changelog

## [3.0.0](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v2.1.1...v3.0.0) (2026-08-14)


### ⚠ BREAKING CHANGES

* **security:** enforce model allowlists -- untag legacy cratestack Value JSON, bump family to 0.7.16 ([#283](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/283))

### Features

* **oauth2:** adopt authkestra-op's handle_token dispatch with a real client registry (ADR-0011 phase 2) ([#288](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/288)) ([70b0a88](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/70b0a8851fd66e356c273fad6cf3cfa69279f9dd))
* **oauth2:** issue a full derived OIDC token object via token-exchange (ADR-0011 phase 1) ([#286](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/286)) ([7194f6b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7194f6b4232ce704aaaa378895f9c19bbcd72b45))


### Bug Fixes

* **security:** enforce model allowlists -- untag legacy cratestack Value JSON, bump family to 0.7.16 ([#283](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/283)) ([c043a64](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c043a64152617f042828051e36f75b869d56bc17))


### Documentation

* **adr:** ADR-0011 — authz issues a derived OIDC token object via token-exchange ([#279](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/279)) ([b723c79](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/b723c79abcb2384352379b7ba084ef822bd2648e))
* **adr:** ADR-0011 — reverse Decision 6, allow offline_access for all clients ([#281](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/281)) ([65fc495](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/65fc49579a474d664753e70ac9dfd5a79e3dc24b))

## [2.1.1](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v2.1.0...v2.1.1) (2026-08-14)


### Documentation

* **agents:** add ADR-0038 persistence rule, correct SQLx-as-design spots ([#235](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/235)) ([653d2da](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/653d2da7d535cecf329cda5c00b33a6a45299993))
* **agents:** add house CUID2 identifier rule (ADR 0039) ([#234](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/234)) ([d4efea9](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/d4efea92063586b08310cf3e5b90019a834a12b9))

## [2.1.0](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v2.0.0...v2.1.0) (2026-08-07)


### Features

* **authz:** add budget:* permissions and RBAC default-grants fallback ([#207](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/207)) ([952bd73](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/952bd73df8ba468e86369199cbc81f769926e361))
* **budget:** add admin review queue (approve/reject) ([#215](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/215)) ([1016450](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/1016450fee2a7334e1f6050e877273513a327ebe))
* **budget:** add ADR-0010 and lightbridge-authz-budget crate skeleton ([#199](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/199)) ([7eccd77](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7eccd7761c38d66d84433c4ebdeee4584498b667))
* **budget:** add augmentation-request ledger and repository ([#213](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/213)) ([938f976](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/938f976016226d46394b2fb28754fab14b38a55d))
* **budget:** add budget_balances table and transactional grant-write path ([#203](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/203)) ([0b9aeaf](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/0b9aeafdaadce43f65b637770b36ac9bf9e77ea7))
* **budget:** add budget_grants ledger migration with append-only enforcement ([#202](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/202)) ([284f8d5](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/284f8d57317cf8ad4068a9718ef3cbfd7df50ead))
* **budget:** add core domain types (AmountMicros, Period, GrantSource, BudgetTier, BudgetError) ([#201](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/201)) ([c642c8a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c642c8a072ddae1d68ef9bc0459a3922fabd707b))
* **budget:** add DB-backed policy storage tied to the rule-data engine ([#209](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/209)) ([f8211d0](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/f8211d041f21b52b4078025e4badc6fa70df678f))
* **budget:** add decision contract, facts, and PolicyEngine trait ([#206](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/206)) ([8dade72](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/8dade72f03f3f70f3db8843abfb297f9a0140ec8))
* **budget:** add ledger replay and expiry-aware balance read ([#205](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/205)) ([15ddf57](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/15ddf5710f89a05c260b33a885f5a560984b0ef6))
* **budget:** add rule-data policy evaluator ([#208](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/208)) ([bf405b0](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/bf405b03cdc16384f4dbf38e7729223c8b284ed8))
* **budget:** add self-service refill orchestration (RefillService) ([#214](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/214)) ([523abe7](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/523abe7b0be5a03b7653f6d31087b86e894b43c7))
* **budget:** add simulateBudgetPolicy RPC procedure ([#212](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/212)) ([2508aa2](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/2508aa2a3c193daf4c5e9cdbcbda64f611f8b45a))
* **budget:** add spend adapter reading usage_events directly ([#204](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/204)) ([3d0cdf1](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/3d0cdf10fe70eb8eef2144e160edb5cc2d9219b2))
* **budget:** stamp and enforce a caller-kind claim to close [#216](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/216) for oauth2.type: self ([#218](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/218)) ([52bc3aa](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/52bc3aaf5f3fd6e93b1807965eb80b788dc4a785))
* **budget:** wire policy activation and status into the RPC surface ([#210](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/210)) ([e0e658a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/e0e658a287482cd19213f8b15057108219451c9b))
* **budget:** wire self-service refill and review queue into the RPC surface ([#217](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/217)) ([1924413](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/1924413f15c85b4dc31e9400b649b291fa26b3a7))


### Bug Fixes

* **deps:** declare jsonwebtoken's crypto backend explicitly ([#186](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/186)) ([84f08dc](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/84f08dc3fe1c7fe22a37cb8abc0ca537ae3124d6))


### Documentation

* **adr,rfc,runbook:** correct budget period to calendar month ([#200](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/200)) ([581fb48](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/581fb483609eebe8dd03b228b202248de71cf41a))
* **adr:** renumber budget-grants ledger ADR 0006 -&gt; 0009 ([#198](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/198)) ([2dfdc39](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/2dfdc39e46940019bbc44a76f0ccadd39418763e))
* budget domain visibility across AGENTS.md/README/architecture.md + fix create_project SQL bug (closes [#211](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/211)) ([#221](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/221)) ([c21b95e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c21b95eb2d56d8e7ae5952f835a1953bf269fd27))

## [2.0.0](https://github.com/ADORSYS-GIS/lightbridge-authz/compare/v1.1.0...v2.0.0) (2026-08-01)


### ⚠ BREAKING CHANGES

* **authz:** type ids as String, not Cuid, in the cratestack schema ([#137](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/137))
* **authz:** migrate authz-api CRUD to cratestack (RPC, CBOR/JSON, RBAC gate) ([#135](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/135))

### Features

* **authz:** add listProjectRoster — the roster had no read path at all ([d81b4ed](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/d81b4ed62c1c42b3ee5bcd4a6397f150fef3d39a))
* **authz:** allow reassigning the default account/project ([#152](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/152)) ([8dce0d0](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/8dce0d06371cec42d5d330aa258e3f3f8dd7062b))
* **authz:** make the RPC surface mount path configurable (server.api.rpc_base_path) ([#136](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/136)) ([92808ea](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/92808eab6a4c5e4afa209ba51a0d8bcb6bc4b900))
* **authz:** migrate authz-api CRUD to cratestack (RPC, CBOR/JSON, RBAC gate) ([#135](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/135)) ([dcf1e71](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/dcf1e715230b25099adc727bd968ad0f4dec3a0e))
* **authz:** project-based governance — project membership supersedes account roles (ADR-0006) ([5b8f605](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/5b8f605279df00df38318cb59b81ad8ccb251ee8))
* **authz:** project-based governance — project membership supersedes account roles (ADR-0006) ([#163](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/163)) ([5b8f605](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/5b8f605279df00df38318cb59b81ad8ccb251ee8))
* **authz:** reconcile ADR-0006 migrations with upstream, remap account ids to subjects ([3fed6a4](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/3fed6a45fb4a02cbcd5de5c919dd89549b3b9aee))
* **authz:** reconcile Phase B schema pivot with upstream [#148](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/148)/[#152](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/152) ([a43e8b5](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/a43e8b543356d2b4660130e28f01c0c3abd5e86c))
* **authz:** resolve the per-member quota tier at introspection ([c4c160b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c4c160b5ede48464590920a6ff533cb4c8adad96))
* **authz:** resolve the per-member quota tier at introspection (ADR-0006 follow-up) ([25a4c8b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/25a4c8bdc2ad9e6de4bbcf091550e0e971ca5a66))
* **authz:** rewrite the repository layer off account_memberships ([a12cda3](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/a12cda3832ee4d5db47fd6024bada16cacdde1ab))
* **authz:** structured env-driven billing plans on API-key creation ([#125](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/125)) ([7e43957](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7e43957baa780db3edb8108a566b4b95e12fb9f7))
* **bearer:** cut over from authkestra-guard to authkestra-resource ([#146](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/146)) ([25202b7](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/25202b7f15c7c2ce2dda07bf68845957c879369e))
* **deps:** move to authkestra 0.3.2 + jsonwebtoken 11, together ([#185](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/185)) ([7ce3c8a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7ce3c8a4a8bff05a7a7a83424de4336db3b2c717))


### Bug Fixes

* **authz:** accept CBOR undefined as null in RPC create/update inputs ([#144](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/144)) ([9f115c3](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/9f115c3d4ca63b9c4a0b9b20a33419f23a3f4b53))
* **authz:** append the new view columns instead of inserting them mid-list ([0e8e40d](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/0e8e40d79472bd1384a94f794f9dfd838876c191))
* **authz:** clean up incorrect multi-default backfill from 20260725000001 ([#156](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/156)) ([52d8895](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/52d8895c88512538bec40e2a29676f085bf74046))
* **authz:** cratestack-redis connection reuse + RPC batch per-frame RBAC ([#165](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/165)) ([1f645d9](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/1f645d968476de7a75f92a2511571bad3940a44c))
* **authz:** drop the unused ProjectMember.account relation — it was the OOM ([bf5a148](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/bf5a1485bd5840a59084c925bfa5bc0871254742))
* **authz:** finish the ADR-0006 migration on the MCP surface (Phase D gap) ([a7eab6b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/a7eab6b27b026122636e6ab52675935b1c03e467))
* **authz:** make the default account/project undeletable, only suspendable ([#148](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/148)) ([65fc730](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/65fc73088edc63ff100b3777acf37f7e289eb5d0))
* **authz:** normalize legacy jsonb-null allowed_models (Project list/get 500) ([#138](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/138)) ([8bb0ff9](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/8bb0ff98a77fd323d9ae707eb8ed09f5b9df9cd6))
* **authz:** normalize legacy plain-{} default_limits (Project list/get 500) ([#139](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/139)) ([b757e5a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/b757e5a74c4c1d4e42a22d82a7dba36eb4c1156f))
* **authz:** scope the Billing imports to the it-tests module ([136ae55](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/136ae55942208a3ac41b5824ce40c3b94e26662f))
* **authz:** type ids as String, not Cuid, in the cratestack schema ([#137](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/137)) ([17cf528](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/17cf528878dda57b56e8429bf49fd3e18edf71c7))
* **charts:** backstop migrate hook Job cleanup with ttlSecondsAfterFinished ([#150](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/150)) ([4cd163c](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/4cd163c7aa935d13175276a57ec216121427c9fb))
* **ci,deps:** revert jsonwebtoken 11.0 regression + cap runner memory usage ([#167](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/167)) ([4274283](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/42742837a23ebbde4f04b95915199d2edda89297))
* **ci,deps:** unbreak the build — bound its memory and restore the cratestack lockstep ([e59c53a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/e59c53a767a66cacf27212bc69770700a9a93a61))
* **ci:** key the s3 artifact prefix on run_id only, not run_attempt ([#140](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/140)) ([859c6ba](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/859c6ba3d74ab2b1767d6e291bca43b825918176))
* **ci:** make container-build resilient — retry mc transfers + decouple from tests ([#141](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/141)) ([09f9fb9](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/09f9fb9fad73d46b3947fa534a70792d6e179c41))
* **ci:** repin security.yml to ai-governance security-gates.yml ([#180](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/180)) ([adbe667](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/adbe6674594e9dda4b13e3857f70667215d2e7d0))
* **deps:** hold jsonwebtoken at 10.x, the version authkestra-guard can consume ([0d066e8](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/0d066e8eee63408e0e150f4d84d55d320113c24f))
* **deps:** restore the cratestack family lockstep at 0.4.16 ([8f502e7](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/8f502e7314243dc72c11b6e8e224c85bad41e0d4))
* **it,deps,ci:** createApiKey response, SAST advisories, missing redis in CI ([#154](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/154)) ([53b0fe6](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/53b0fe66ac904e49cf9e5f588b367e72d26c285e))
* **lints:** enable unwrap_used and redundant_clone gates ([#183](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/183)) ([d8bb9d6](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/d8bb9d6ff5ca1f9ac39ee17d48a12512e8c0b719))
* **rest:** pass dev_cors arg in RBAC router tests so --all-targets compiles ([efa2033](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/efa2033881f55d9f6870c5deba8ff3ba455b428d))


### Performance Improvements

* **authz:** drop the redundant account fetch from introspection ([ccba11e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/ccba11e3972f99e2c3b9d4cf1928afb77e536edd))
* **ci:** give it-authorino more retry budget for rootless DNS flakes ([#168](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/168)) ([4f0504b](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/4f0504b0b6a4f42e1e83340ebb385547e175e1c9))
* **ci:** stop the Rust build from OOM-killing runners and dev machines ([8430653](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/84306533e0a231f0ff8e6fc22abb520e4d639e60))
* **test:** bound acquire_timeout on dead test pools — 811s to 7s ([c3e017f](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c3e017faf2fcafdd51d8ed97123caf60d5cb610f))


### Continuous Integration

* cap cargo jobs at 2 again and add swap headroom ([2721fdd](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/2721fdd7cb0d508a9380eec5708160a60a121d69))
* drop cargo to a single job — two 7 GB compile units do not fit ([3d44cd4](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/3d44cd46743395f3762102b47be8b88b552f7cd6))
* instrument the cargo check step to diagnose the exit-143 kills ([68fc5b1](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/68fc5b183998071b3599f97eceaa0240c4772eba))
* move every workflow onto public GitHub runners ([fe1b8c6](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/fe1b8c681c4bcda4cfad20c04838bfe6963ffda6))
* raise swap to 32G — the single rustc needs ~25G and was still growing ([5df436f](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/5df436f9670cf8a55a46db933baf7319e9af66c5))
* stand down systemd-oomd around the heavy cargo steps ([7d25f77](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7d25f77cc4cf2e2c5d6ba31ef83d0f598b82cead))
* stop CI firing twice per push and cancelling itself ([760730d](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/760730d841bf0f4f516ac7b8cc7940c3e8b2fcfc))
* undo the scaffolding built while chasing the schema bug ([c3e0c7a](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/c3e0c7ad2d2d312ebfd4984dc9c4174b6141f93b))


### Build System

* **lints:** add measured clippy/rustfmt gates and the judgment rules ([#182](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/182)) ([d71619c](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/d71619c2d3d02c8d45c39b44143d3e99a1ef103c))


### Documentation

* **adr:** record that introspection stays authoritative and the allowlist is enforceable ([3d16f0e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/3d16f0e66fa2a8a8d0ee8cad38272daea1025b00))
* **adr:** record why dropping account members is safe, not just intended ([609dc69](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/609dc69695756196c4e224648596ec034d14387b))
* **authz:** explain the governance model and how it is actually enforced ([82e58ea](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/82e58ea968a3866db1ca7c073fac3af6160dda44))
* **authz:** explain the governance model and how it is actually enforced ([f508e8e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/f508e8ea653ea723d6e3ddfa4dbe86c69b3bc950))
* **authz:** record the ADR-0006 reconciliation and rewrite the membership docs ([7ef70a5](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/7ef70a53b13754b9aeac97a7ae399fbfde79a0b4))
* **authz:** record the live filter order and the 30-day budget window ([3f2379f](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/3f2379f11391b1d7a2c43f78b7a7a67a875efca4))
* **authz:** record the live filter order and the 30-day budget window ([1517338](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/1517338f189d1e8caf80031712241555bd457225))
* **authz:** render the governance diagrams in mermaid ([9225fa8](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/9225fa8e8f1a1c449a8b1f8d64148ffcbf6fc124))
* **authz:** retire the last account_memberships references in rest-crate doc comments ([42b36f4](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/42b36f41b1e761e941fa6a84e26350f14741b9cd))
* **deps:** link the upstream authkestra jsonwebtoken-11 tracking issue ([8045b6e](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/8045b6eb12c21d59bad183c7d9b2f3d0e6d6257f))
* document the prod-profile fat-LTO tradeoff in Cargo.toml ([9ab82ea](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/9ab82ea0e343b1c1a4a8124be660f486c4528864))
* specify dynamic budget refill (ADR-0006/0007/0008, RFC-0001) ([#178](https://github.com/ADORSYS-GIS/lightbridge-authz/issues/178)) ([0db726c](https://github.com/ADORSYS-GIS/lightbridge-authz/commit/0db726c16c4e4fa97fab4bfc00a80f15c97a9932))

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
