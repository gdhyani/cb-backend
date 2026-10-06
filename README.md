# cb-backend

The API and credential gateway for cb: the only part of cb that holds real secrets, so developers can run apps against real services without ever seeing a credential.

**Documentation:** the cb dashboard serves the docs at `/docs`; their source is in
[`content/docs/`](https://github.com/gdhyani/cb-dashboard/tree/main/content/docs) of gdhyani/cb-dashboard.

## Run

```bash
npm install
cp .env.example .env        # set MONGODB_URI, MASTER_KEY and SERVER_SECRET (openssl rand -base64 32)
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

## Test services

`docker-compose.test.yml` starts password-protected Redis, PostgreSQL, MySQL (plain and TLS-only), an SMTP
server and S3-compatible storage for gateway tests. No passwords live in the file; export them first:

```bash
export CB_TEST_DB_PASSWORD=… CB_TEST_REDIS_PASSWORD=…
docker compose -f docker-compose.test.yml up -d --wait
```

## API conventions

Every REST response uses one envelope — `{ success: true, data, meta: { correlationId, pagination? } }` —
and every error one shape — `{ success: false, error: { code, message, statusCode, details?, correlationId } }`.
Send `x-correlation-id` to trace a flow through the logs.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
