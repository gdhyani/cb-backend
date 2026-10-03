# cb-backend

API and credential gateway for cb. Structure, conventions and rules: see the repo guide (`CLAUDE.md`).

## Run

```bash
npm install
cp .env.example .env        # set MONGODB_URI
npm run dev                 # nodemon, http://localhost:4200
curl localhost:4200/api/health
```

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Dev server with reload (nodemon + tsx), loads `.env` |
| `npm run build` / `npm start` | Compile to `dist/` / run the compiled server |
| `npm test` | Unit + integration tests (in-memory MongoDB) |
| `npm run typecheck` / `npm run lint` | TypeScript / Biome |

## API conventions

Every REST response uses one envelope — `{ success: true, data, meta: { correlationId, pagination? } }` —
and every error one shape — `{ success: false, error: { code, message, statusCode, details?, correlationId } }`.
Send `x-correlation-id` to trace a flow through the logs.
