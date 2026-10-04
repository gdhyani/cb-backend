# cb tunnel protocol (v0)

The `/tunnel` WebSocket is the gateway data plane between the cb agent (`cb-env`) and `cb-backend`
(PRD §10.7, §12.2). The agent is a thin byte pipe: it never sees a real secret and never parses
protocols. All protocol-aware logic lives in `src/gateway/` on the backend.

Implementation: `src/gateway/tunnel.ts`. Contract version follows `x-contract-version` in `openapi.yaml`.

## 1. Opening a tunnel

```
GET ws(s)://<backend>/tunnel?layer=1&env=<envId>&resource=<resourceId>
GET ws(s)://<backend>/tunnel?layer=2&env=<envId>&host=<host>&port=<port>
Authorization: Bearer <device token>
```

One tunnel carries exactly one client connection (one TCP connection accepted by an agent listener).

### Query parameters

| Layer | Param | Rule |
|---|---|---|
| both | `layer` | `"1"` or `"2"` |
| both | `env` | environment id, 24 hex chars |
| 1 | `resource` | resource id, 24 hex chars; must belong to `env` and not be disabled |
| 2 | `host` | 1–253 chars; matched case-insensitively |
| 2 | `port` | integer 1–65535 |

- **Layer 1** (listener per resource): the app connects to `127.0.0.1:<port>` from the snapshot's
  `listeners[]`; the agent opens a tunnel naming that resource.
- **Layer 2** (host redirection): the app connects to a real hostname (e.g. `api.example.com:443`)
  listed in the snapshot's `redirects[]`; the agent forwards it with `host` + `port`. The backend picks the
  enabled resource in `env` whose `config.redirectHosts` contains `host:port`. Only `http`, `oauth`,
  `google-sa` and `apns` resources are reachable through Layer 2 (`aws` is Layer 1 only).

### Authentication

- `Authorization: Bearer <token>` with a CLI device token (prefix `cbd_`, from the device-code flow).
  The same token is used for the REST `/api/cli/*` and `/api/agent/*` endpoints.
- The token must resolve to a non-revoked, non-expired device of an active user. Use extends the
  device's rolling 30-day expiry.
- The agent may also send `X-CB-Agent-Version: <semver>` (PRD §12.2); the backend does not require it.

### Authorization order

The server accepts the WebSocket upgrade first, so every refusal arrives as a close code (§3):

1. Device token valid → else `4401`.
2. Query parameters valid → else `4403`.
3. Environment exists and a matching resource exists (Layer 1: by id; Layer 2: by redirect host) → else `4403`.
4. Runtime access: the user is a member and is an owner/admin or holds an active, unexpired grant
   (environment- or project-scoped) and the environment is not killed. A killed environment closes
   with `4410`; any other denial with `4403`. HTTP-family resources instead receive a readable
   `403 {"error":"cb_access_revoked"}` HTTP response inside the tunnel (see §4).
5. The user's credential profile for the resource resolves (environment grant's choice, then the
   project grant's, then `default`). A profile that no longer exists → `4403`.

Every decision is audited (`tunnel.denied`, `tunnel.opened`, `tunnel.closed` with bytes in/out and duration).

## 2. Framing

After `101 Switching Protocols`, **binary frames carry raw bytes in both directions**. There is no
extra framing, header or multiplexing: concatenating the frame payloads yields the exact TCP byte stream.

- Per-message deflate is disabled. Maximum frame payload: 64 MiB.
- The client may send its first bytes immediately after the upgrade; the server buffers them until
  authorization finishes.
- Either side closing the WebSocket ends the client connection; the agent closes the local socket.

## 3. Close codes

| Code | Name | Sent when | Agent behaviour |
|---|---|---|---|
| 1000 | Normal | The tunnel finished normally | Close the local socket |
| 1001 | Going away | The backend is shutting down | Close the local socket; reconnect on the next client connection |
| 4401 | Unauthorized | Token missing, invalid, expired or the device is revoked | Stop; tell the user to run `cb login` |
| 4403 | Forbidden | Bad parameters, unknown environment/resource, no grant / not a member, profile gone | Log a clear message naming the resource and environment |
| 4410 | Revoked | Access revoked while open, or the environment is killed | Mark the snapshot revoked; notify `cb run` |
| 4502 | Upstream failed | Upstream unreachable, upstream auth failed, or a gateway error | Log the secret-free summary in the close reason |

Close reasons are human-readable, at most 120 characters, and never contain secrets. PRD §12.2 also
reserves `4429` (rate limited); the backend does not send it yet (FR-GW-009 rate limiting defaults off).

## 4. What runs inside a tunnel

The backend feeds the byte stream into an adapter selected by the resource kind:

| Kinds | Layer 1 | Layer 2 |
|---|---|---|
| `postgres`, `mysql`, `mongodb`, `redis`, `smtp` | Protocol-native adapter: verifies the fake credential, authenticates upstream with the real one, then pipes | — |
| `http`, `oauth`, `aws`, `google-sa`, `apns` | Plain HTTP/1.1 server inside the tunnel | TLS terminated in the backend, then HTTP/2 or HTTP/1.1 by ALPN |

### Layer 2 TLS termination

- The app speaks TLS to what it believes is the real host. The backend terminates it with a **leaf
  certificate minted from the organization's CA** for the SNI hostname (ECDSA P-256, SHA-256,
  SAN = the hostname, `serverAuth`, 30-day validity, cached per hostname in memory).
- The app trusts that leaf because the agent installs the org CA (`orgCaCert` in the bootstrap snapshot)
  into the app process only — never system-wide (PRD §17.3).
- ALPN negotiates `h2` or `http/1.1`; requests then go to the resource's HTTP adapter, which swaps the
  fake credential for the real one and forwards to the upstream with **verified** TLS (FR-GW-004).
- Upstream response bodies are redacted (real secret → `[cb-redacted]`, FR-GW-006). Upstream failures
  inside an HTTP adapter return `502 {"error":"cb_upstream_unreachable"}`.

## 5. Revocation

- Revocations travel over the backend event bus as `access.revoked` with a scope: `grant`, `device`,
  `membership`, `environment` or `project` (grant revoked or expired, device revoked, member removed
  or demoted, environment killed or deleted, project deleted, credential profile assignment changed).
- For every live tunnel the event may concern, the backend **re-checks access against the database**
  (S3). If access is gone — or the user's credential profile for that resource changed — the tunnel
  closes with **`4410`** and a reason such as `access revoked (access revoked by admin)`, within ≤ 5 s
  (FR-GW-007).
- Adapters may register a hook that writes a protocol-native error just before the close
  ("cb: access revoked by admin"); HTTP clients that reconnect after revocation receive
  `403 {"error":"cb_access_revoked"}`.
- The agent learns about the same events via `GET /api/agent/events` (SSE: `access.revoked`,
  `config.changed`) and re-fetches `GET /api/agent/bootstrap` on `config.changed`.
- The real secret held for a tunnel is cleared when it closes. Credential rotation applies to new
  connections; open tunnels keep their upstream session.

## 6. Agent event stream (`GET /api/agent/events?envId=…`)

Server-sent events for one device + environment: `ready` (on open), `heartbeat` (every 15 s), `config.changed`,
`access.revoked` and `webhook`. Agents treat **45 s without any bytes** as a dead connection and reconnect;
every reconnect uses a fresh access token.

### `webhook` (FR-WH-003)

```json
{ "deliveryId": "…", "generation": 0, "eventId": "evt_…", "provider": "stripe", "type": "payment_intent.succeeded",
  "path": "/api/webhooks/stripe", "port": null, "headers": { "content-type": "application/json",
  "stripe-signature": "t=…,v1=…" }, "body": "<base64>" }
```

- Sent only to the device that created the objects the event names (or that opted in with
  `POST /api/agent/webhooks/listen`). Headers are signed with **this device's fake** signing secret (fresh
  timestamp per attempt); the real secret never leaves the backend.
- The agent posts `body` (bytes unchanged) with `headers` to `http://127.0.0.1:<port><path>`, then calls
  `POST /api/agent/webhooks/{deliveryId}/ack` with `{ ok, status?, error?, ms? }` (`ok` = the app answered 2xx).
- At-least-once: pending deliveries are re-sent on every stream open and when no ack arrives within 30 s.
  Agents remember recent `deliveryId` + `generation` pairs and re-ack a repeat without posting it to the app
  again; a dashboard Replay bumps `generation`, so it is posted once more. Acks carry the `generation` they answer.
- No app attached under `cb run` → ack `{ ok: false, noApp: true }` (not a failed attempt). When a `cb run`
  attaches, the agent calls `POST /api/agent/webhooks/redeliver` with the project and environment.
- Port: `cb run --webhook-port` → `.cb/project.json` `webhookPort` → `PORT` of the `cb run` command →
  `port` from the event → 3000.
