# cb-backend — API + Gateway (Express 5 + MongoDB)

The only component that holds real secrets. Serves the REST API (dashboard + CLI), the agent
bootstrap/events endpoints, and the `/tunnel` WebSocket gateway with every protocol adapter.

- PRD: `../product.md` (§10 is this repo; §12 contracts; §13 security). Workspace rules: `../CLAUDE.md`.
- Decisions → PRD §20, open questions → PRD §19 (no separate files).
- **Owns the contracts** in `contracts/`. Change them here first; consumers re-sync.

## Git & GitHub

- **Before any git or GitHub operation** (commit, branch, push, PR, merge), read `GITHUB.md`
  at this repo's root. It is local-only and gitignored; it holds the account, commit identity, PR commands and
  attribution rules. If it is missing, stop and ask the owner — never guess accounts or identities.
- Every change goes on a new branch → pull request → merge into `main`. Never commit to `main` directly.
- **Keep `../product.md` current:** any change to structure, tooling, contracts, defaults or behaviour is
  written into the PRD and logged in PRD §20 with a version bump, in the same change.

- **Docs stay local:** everything under `docs/` (plans, specs, trial notes) is gitignored and never
  pushed. Do not commit plan or design documents anywhere else in the repo.

## Hard rules for this repo

- **No endpoint ever returns stored secret plaintext** (L15, S2) — enforced by a test that
  scans every response schema/route. Secret fields are `select: false` in Mongoose.
- Real secrets are decrypted **per use**, held only as long as needed, **never logged** (FR-GW-005, S9).
- Upstream TLS **always verifies** (FR-GW-004). `UPSTREAM_EXTRA_CA_FILE` is test-only and the
  process refuses to start with it when `NODE_ENV=production` (S11).
- Fake-credential checks use **constant-time** comparison (FR-CRY-002, S7).
- Revocation closes affected tunnels in **≤ 5 s** with protocol-native errors (FR-GW-007, S4).
- Adapter **presets are data (JSON)**, not new code paths (§10.8 http presets).
- Crypto and event bus sit behind **interfaces** (KMS / Redis bus later — FR-CRY-001, FR-EVT-001).

## Folder structure

```
cb-backend/
├─ src/
│  ├─ constants.ts            # product names, ports, close codes, formats — rename here
│  ├─ server.ts               # entry: config → db → app → http.Server (+ ws upgrade)
│  ├─ app.ts                  # Express app (API) sharing the http.Server with ws
│  ├─ config.ts               # zod-parsed env (PRD §10.2)
│  ├─ logger.ts               # pino + redaction paths (S9)
│  ├─ db/
│  │  ├─ connect.ts
│  │  └─ models/              # one file per collection (PRD §10.3) + indexes
│  ├─ auth/
│  │  ├─ passwords.ts         # argon2id (FR-CRY-006)
│  │  ├─ dashboard-session.ts # httpOnly SameSite=Lax cookie, CSRF (FR-AUTH-001)
│  │  ├─ device-code.ts       # FR-AUTH-002
│  │  ├─ tokens.ts            # ES256 JWT, refresh rotation + reuse detection (FR-AUTH-003/004)
│  │  ├─ jwks.ts              # /.well-known/jwks.json
│  │  └─ rate-limit.ts        # login per IP + per email
│  ├─ api/                    # routers (PRD §10.6), each with zod request + response schemas
│  │  ├─ orgs.ts  members.ts  invites.ts  projects.ts  environments.ts
│  │  ├─ resources.ts  profiles.ts  presets.ts  variables.ts  preview.ts  grants.ts
│  │  ├─ sessions.ts  devices.ts  killswitches.ts  audit.ts
│  │  └─ agent.ts             # /agent/bootstrap, /agent/events (SSE), /agent/heartbeat
│  ├─ services/               # business logic used by routers + gateway (authz, snapshot render)
│  │  ├─ authorize.ts         # the FR-GW-001 ordered checks, shared by API + gateway
│  │  └─ snapshot.ts          # renders env/redirects/fakeFiles for bootstrap (§12.4)
│  ├─ events/
│  │  ├─ bus.ts               # EventBus interface + in-process impl (FR-EVT-001)
│  │  └─ sse.ts               # FR-EVT-002
│  ├─ crypto/
│  │  ├─ envelope.ts          # DEK + AES-256-GCM, wrapped by MASTER_KEY (FR-CRY-001)
│  │  ├─ derive.ts            # HMAC fakes + generated secrets + formats (FR-CRY-002/003, §12.5)
│  │  ├─ keymat.ts            # fake Firebase RSA / APNs EC key material (FR-CRY-004)
│  │  └─ ca.ts                # org CA + per-SNI leaf certs, cached (FR-CRY-005)
│  ├─ gateway/
│  │  ├─ tunnel.ts            # WSS /tunnel: auth, authz, dispatch, close codes (FR-GW-001/002)
│  │  ├─ ws-duplex.ts         # WebSocket ↔ Node Duplex with backpressure
│  │  ├─ tls-terminator.ts    # Layer 2: SNI → leaf, ALPN h2/http1.1 → internal servers (FR-GW-003)
│  │  ├─ http-router.ts       # route request to adapter whose matches(host, req) is true
│  │  ├─ upstream-tls.ts      # verified TLS to real services (FR-GW-004)
│  │  ├─ redaction.ts         # strip real secret bytes + base64 (FR-GW-006)
│  │  ├─ revocation.ts        # bus subscriber, closes tunnels ≤5 s (FR-GW-007)
│  │  ├─ ratelimit.ts         # token bucket, default off (FR-GW-009)
│  │  ├─ presets/             # JSON presets: openai, anthropic, stripe, razorpay, generic …
│  │  └─ adapters/
│  │     ├─ types.ts          # Adapter interface (stream adapters + HTTP adapters)
│  │     ├─ postgres/  mysql/  mongodb/  redis/      # wire-protocol adapters
│  │     ├─ http/             # preset-driven HTTP adapter (SSE/chunked streaming)
│  │     ├─ aws/              # SigV4 verify + re-sign, presign, aws-chunked
│  │     ├─ smtp/
│  │     ├─ oauth/            # Google, GitHub, generic token URL
│  │     ├─ google-sa/        # Firebase Admin / FCM, tokenSwaps
│  │     └─ apns/             # HTTP/2 provider JWT swap
│  ├─ audit/
│  │  └─ audit.ts             # trusted audit writer (FR-GW-008, J8)
│  └─ trial/                  # M0 only: seeded config + static dev token; removed/folded in M1
├─ contracts/
│  ├─ openapi.yaml            # REST contract, source of truth (x-contract-version)
│  └─ tunnel-protocol.md      # tunnel + events + snapshot contracts
├─ test/
│  ├─ unit/
│  ├─ integration/            # API on ephemeral MongoDB; adapters vs docker-compose services
│  ├─ mocks/upstreams/        # mock HTTPS upstreams on a test CA (stripe, openai SSE, apns h2 …)
│  └─ security/               # canaries, "no secret in any response", log redaction
├─ docs/                    # LOCAL ONLY (gitignored): plans/, notes
├─ docker-compose.test.yml    # Postgres 16, MySQL 8, Mongo 7 RS, Redis 7 ACL, MinIO, Mailpit, backend Mongo
├─ README.md  CLAUDE.md
├─ biome.json  tsconfig.json  vitest.config.ts
└─ package.json
```

## Configuration (env, zod-validated in `src/config.ts`)

`PORT` (4000) · `MONGODB_URI` · `MASTER_KEY` (32-byte base64) · `SERVER_SECRET` (32-byte base64) ·
`JWT_SIGNING_KEY` (ES256 PEM) · `PUBLIC_URL` · `DASHBOARD_URL` · `UPSTREAM_EXTRA_CA_FILE` (test only).
Keep a `.env.example` with placeholder values only.

## Tools

| Tool | Use |
|---|---|
| TypeScript (`strict`) | Language; `tsc` build, `tsx` for dev run |
| Vitest | Unit + integration tests |
| Biome | Lint + format |
| Docker Compose | Test dependencies only (`docker-compose.test.yml`, L14) |
| `@redocly/cli` (proposed) | Lint `contracts/openapi.yaml` |

## Packages

No restrictions: install at milestone start, latest stable, most relevant for the job.
The lists below are starting points.

**Specified by the PRD**

| Package | Why |
|---|---|
| `express` (v5) | HTTP API |
| `mongoose` | MongoDB models |
| `ws` | `/tunnel` WebSocket |
| `pino` (+ `pino-http`) | JSON logs with request/tunnel IDs |
| `zod` | Config, request/response, WS params |
| `@node-rs/argon2` | argon2id password hashing |
| `vitest`, `@biomejs/biome`, `typescript`, `tsx` (dev) | Tooling |

**Initial picks (not in PRD — use latest stable; swap freely for something better, note it in PRD §20)**

| Package | Why |
|---|---|
| `jose` | ES256 JWT sign/verify + JWKS |
| `@peculiar/x509` (or `node-forge`) | Org CA + leaf certificate minting |
| `cookie-parser` + `csrf-csrf` | Dashboard cookie session + CSRF |
| `express-rate-limit` | Login rate limiting |
| `@aws-sdk/signature-v4` + `@smithy/protocol-http` | Re-signing in the aws adapter |
| `mongodb` | Primary discovery (`mongodb+srv`) in the mongodb adapter; "test connection" |
| `pg`, `mysql2`, `ioredis`, `nodemailer` | "Test connection" from the gateway only — wire adapters stay hand-written |
| `mongodb-memory-server` (dev) | Ephemeral MongoDB for API integration tests |
| `zod-to-openapi` (`@asteasolutions/zod-to-openapi`) | Keep openapi.yaml in sync with zod schemas |

## Commands

```bash
npm run dev              # tsx watch src/server.ts  (port 4000)
npm run build            # tsc → dist/
npm test                 # unit + API integration (mongodb-memory-server)
npm run test:adapters    # adapter integration vs docker-compose.test.yml services
npm run test:canary      # security suite
npm run lint             # biome check (+ openapi lint)
docker compose -f docker-compose.test.yml up -d
```

## Testing notes

- Every adapter: integration test against the real service in Docker **plus** a canary
  assertion that the real secret never comes back to the client.
- Mock upstreams assert they received the canary real secret and **never** a fake.
- Authz order in FR-GW-001 is tested case-by-case, each with the expected close code (§12.2).
