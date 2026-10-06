# cb-backend — API + Gateway (Express 5 + MongoDB)

The only component that holds real secrets. Serves the REST API (dashboard + CLI), the agent
bootstrap/events endpoints, and the `/tunnel` WebSocket gateway with every protocol adapter.

- PRD: `../product.md` (§10 is this repo; §12 contracts incl. §12.7 envelope/errors; §13 security).
- Decisions → PRD §20, open questions → PRD §19 (no separate files).
- **Owns the contracts** in `contracts/`. Change them here first; consumers re-sync.

## Git & GitHub

- **Before any git or GitHub operation** (commit, branch, push, PR, merge), read `GITHUB.md`
  at this repo's root. It is local-only and gitignored. If it is missing, stop and ask the owner.
- Every change goes on a new branch → pull request → merge into `main`. Never commit to `main` directly.
- **Keep `../product.md` current:** any change to structure, tooling, contracts, defaults or behaviour is
  written into the PRD and logged in PRD §20 with a version bump, in the same change.
- **Keep the public docs current (FR-DOC-008):** every change merged into `main` that a user or contributor can
  see (CLI commands/flags, API, config/env vars, connectors, error messages, limits, setup) updates the matching
  page in `../cb-dashboard/content/docs/` (and affected screenshots) together with `../product.md`. Open that docs
  PR in cb-dashboard alongside this one and merge it no later than the code PR. Nothing user-visible changed →
  the PR description says `Docs: not needed — <reason>`.
- **Docs stay local:** everything under `docs/` (plans, notes) is gitignored and never pushed.

## Hard rules for this repo

- **No endpoint ever returns stored secret plaintext** (L15, S2) — test-enforced. Secret fields are
  `select: false` in Mongoose.
- Real secrets are decrypted **per use**, held only as long as needed, **never logged** (FR-GW-005, S9).
- Upstream URLs are https; plain `http://` only for private/loopback addresses (`src/utils/upstream-url.ts`, PRD v1.26 D11).
- Adding a key with its service is one call (`POST /api/environments/:envId/services`): tested first, nothing saved on failure.
- Upstream TLS **always verifies** (FR-GW-004). `UPSTREAM_EXTRA_CA_FILE` is test-only; startup refuses
  it when `NODE_ENV=production` (S11).
- Fake-credential checks use **constant-time** comparison (FR-CRY-002, S7).
- Revocation closes affected tunnels in **≤ 5 s** with protocol-native errors (FR-GW-007, S4).
- Adapter **presets are data (JSON)**, not new code paths (§10.8).
- Crypto and event bus sit behind **interfaces** (KMS / Redis bus later — FR-CRY-001, FR-EVT-001).

## Folder structure (layered, one file per module per layer)

Naming: `<module>.<layer>.ts` — e.g. `project.routes.ts`, `project.controller.ts`,
`project.service.ts`, `project.model.ts`, `project.schema.ts`, `mongodb.client.ts`.

```
cb-backend/
├─ src/
│  ├─ index.ts                 # entry: calls startup() from lifecycle
│  ├─ lifecycle.ts             # startup (env check → clients connect → listen) + graceful shutdown
│  ├─ app.ts                   # builds the Express app: registerMiddlewares → routes → error handlers
│  ├─ server.ts                # http.Server + ws upgrade (/tunnel) around the app
│  ├─ constants.ts             # product names, ports, close codes, formats — rename here
│  ├─ config/
│  │  └─ env.ts                # zod-validated env; prints every invalid/missing var and exits(1)
│  ├─ clients/                 # ONE file per external system we connect to; connect()/disconnect()/health()
│  │  ├─ mongodb.client.ts
│  │  └─ upstream-http.client.ts   # undici dispatchers for real providers (verified TLS)
│  ├─ models/                  # Mongoose models, one per collection (PRD §10.3): project.model.ts …
│  ├─ schemas/                 # zod request/response schemas per module: project.schema.ts …
│  ├─ routes/
│  │  ├─ index.ts              # mounts every *.routes.ts under /api, /auth, /cli, /agent
│  │  └─ project.routes.ts …   # path + validate(schema) + controller; no logic
│  ├─ controllers/             # HTTP edge: parse → call service → sendSuccess / next(AppError)
│  │  └─ project.controller.ts …
│  ├─ services/                # business logic; throw AppError; no req/res
│  │  └─ project.service.ts …
│  ├─ middlewares/
│  │  ├─ index.ts              # registerMiddlewares(app): the ONE place middleware order is defined
│  │  ├─ correlation-id.middleware.ts
│  │  ├─ request-logger.middleware.ts
│  │  ├─ auth.middleware.ts  csrf.middleware.ts  validate.middleware.ts  rate-limit.middleware.ts
│  │  ├─ not-found.middleware.ts
│  │  └─ error-handler.middleware.ts
│  ├─ errors/
│  │  ├─ app-error.ts          # AppError class (the ONLY error type sent to clients)
│  │  ├─ error-codes.ts        # code → default status + message catalog
│  │  └─ to-app-error.ts       # unknown/zod/mongoose errors → AppError (+ controller context)
│  ├─ utils/
│  │  └─ response.ts           # sendSuccess / sendPaginated — the ONE way to send data
│  ├─ logger/
│  │  ├─ logger.ts             # winston: JSON in prod, readable in dev, redaction (S9)
│  │  └─ context.ts            # AsyncLocalStorage: correlationId, userId on every log line
│  ├─ crypto/                  # envelope encryption, HMAC derivations, CA + leaf certs, keymat
│  ├─ events/                  # EventBus interface + in-process impl; SSE writer
│  ├─ gateway/                 # data plane (not REST): tunnel, tls-terminator, adapters/, presets/
│  └─ trial/                   # M0 only: seeded config + static dev token + mock upstreams
├─ contracts/                  # openapi.yaml (x-contract-version), tunnel-protocol.md
├─ test/                       # unit/, integration/, security/, helpers/
├─ docs/                       # LOCAL ONLY (gitignored)
├─ docker-compose.test.yml
├─ nodemon.json  biome.json  tsconfig.json  vitest.config.ts  .env.example
└─ package.json
```

## API contract: one envelope, one error (PRD §12.7 — mirrored exactly in cb-dashboard and cb-env)

```jsonc
// success
{ "success": true, "data": { /* T */ }, "meta": { "correlationId": "…" } }
// paginated list
{ "success": true, "data": [ /* T[] */ ],
  "meta": { "correlationId": "…",
            "pagination": { "page": 1, "pageSize": 20, "total": 134, "totalPages": 7, "hasNext": true, "hasPrev": false } } }
// error
{ "success": false,
  "error": { "code": "PROJECT_NOT_FOUND", "message": "Project not found", "statusCode": 404,
             "details": [ { "path": "slug", "message": "…" } ],   // optional (validation)
             "correlationId": "…" } }
```

- Controllers send data **only** via `sendSuccess(res, data, status?)` / `sendPaginated(res, items, pagination)`.
- Errors reach clients **only** through `error-handler.middleware.ts` as the error shape above.
- Error `code`s are SCREAMING_SNAKE_CASE from `errors/error-codes.ts`; never invent ad-hoc codes inline.
- The gateway data plane (tunnel close codes, adapter responses to app SDKs such as
  `403 {"error":"cb_access_revoked"}`) follows PRD §10.7/§12.2, not this envelope.

## Error flow (every controller, no exceptions)

Services throw `AppError` (or let unexpected errors bubble). Controllers wrap every handler in
`try/catch` and pass the error to `next()` with a **context string** naming where and what failed.
The error handler logs it once and sends the envelope.

```ts
// services/project.service.ts
export async function getProject(id: string) {
  const project = await ProjectModel.findById(id).lean();
  if (!project) throw new AppError("PROJECT_NOT_FOUND", { details: [{ path: "id", message: id }] });
  return project;
}

// controllers/project.controller.ts
export async function getProjectHandler(req: Request, res: Response, next: NextFunction) {
  try {
    const project = await projectService.getProject(req.params.id);
    sendSuccess(res, project);
  } catch (err) {
    next(toAppError(err, "project.controller.getProject: failed to load project"));
  }
}
```

- `AppError` fields: `code`, `message`, `statusCode`, `details?`, `context?` (controller string, logs
  only — never sent), `cause?` (original error, logs only), `isOperational` (true for expected 4xx/known 5xx).
- `toAppError(err, context)`: passes `AppError` through (adding context), maps zod → `VALIDATION_FAILED`
  (400 + details), Mongo duplicate key → `CONFLICT` (409), anything else → `INTERNAL_ERROR` (500,
  `isOperational: false`, generic client message).

## Logging (winston) — readable outcome first, stack only when it matters

- Every log line carries `correlationId` (from `x-correlation-id` request header, generated if absent,
  echoed in the response header and `meta.correlationId`).
- Request log, one line per request on finish:
  `INFO  [c0ffee12] GET /api/projects/abc → 200 OK 14ms user=u_1`
- Error log, written by the error handler using the controller context:
  `WARN  [c0ffee12] GET /api/projects/abc → 404 PROJECT_NOT_FOUND — project.controller.getProject: failed to load project`
- **Stack traces only** for non-operational errors (`statusCode >= 500` or `isOperational === false`):
  `ERROR [c0ffee12] POST /api/resources → 500 INTERNAL_ERROR — resource.controller.create: … \n<stack>`
- 4xx → `warn`, 5xx → `error`, lifecycle/startup → `info`. Dev: colorized single-line; prod: JSON for
  later observability. Redact tokens, cookies, `authorization`, secret fields (S9).

## Lifecycle

- **Startup** (`lifecycle.ts`): validate env (fail fast listing every problem) → connect each client
  in `clients/` and check health → build app + server → listen → log `ready on :4200 (env=development)`.
- **Shutdown** on `SIGINT`/`SIGTERM`: stop accepting connections → close tunnels/SSE (send close codes)
  → close http server (timeout 10 s, then force) → disconnect clients → flush logger → exit 0.
- `uncaughtException` / `unhandledRejection` → log fatal with stack → graceful shutdown → exit 1.
- Dev runs under **nodemon** (`nodemon.json`: watch `src`, ext `ts,json`, exec `tsx src/index.ts`).

## Configuration (env, validated in `src/config/env.ts`)

`NODE_ENV` · `PORT` (4200) · `LOG_LEVEL` (info) · `MONGODB_URI` · `MASTER_KEY` (32-byte base64) ·
`SERVER_SECRET` (32-byte base64) · `JWT_SIGNING_KEY` (ES256 PEM) · `PUBLIC_URL` · `DASHBOARD_URL` ·
`UPSTREAM_EXTRA_CA_FILE` (test only). Each milestone adds only the vars it needs. `.env.example`
holds placeholders only.

## Tools & packages

No restrictions — latest stable, most relevant, installed when a task needs it. Starting points:

| Package | Why |
|---|---|
| `express` v5, `ws`, `zod`, `mongoose` | API, tunnel, validation, models |
| `winston` | Structured logging (dev pretty, prod JSON) |
| `nodemon` + `tsx` (dev) | Dev server with reload |
| `@node-rs/argon2`, `jose`, `@peculiar/x509` | Passwords, JWT/JWKS, CA + leaves |
| `undici` | Upstream HTTP with verified TLS + pooling |
| `cookie-parser`, `csrf-csrf`, `express-rate-limit`, `helmet`, `cors` | Middleware |
| `vitest`, `supertest`, `mongodb-memory-server`, `@biomejs/biome`, `typescript` (dev) | Tooling |

## Commands

```bash
npm run dev              # nodemon → tsx src/index.ts (port 4200)
npm run build            # tsc → dist/
npm start                # node dist/index.js
npm test                 # vitest
npm run lint             # biome check
npm run trial:stack      # M0 only: mock upstreams + seeded gateway for cb-env e2e
```

## Testing notes

- Every FR has ≥1 test named with its ID. Controllers tested via supertest against `createApp()`.
- Envelope and error shapes are asserted in tests (`success`, `data`, `meta.correlationId`, `error.code`).
- Every adapter: integration test against the real service in Docker **plus** a canary assertion.
- Mock upstreams assert they received the canary real secret and **never** a fake.
