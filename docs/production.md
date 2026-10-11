# Production deployment

CI performs linting, runtime regression tests, a wheel build, and installation outside the source checkout. Install with `python -m pip install '.[api,dev]'`, or use Docker Compose after copying `.env.example` to `.env`.

Set a randomly generated `SCANNER_API_KEY` before remote API exposure. Send it as `X-API-Key` for scans, reports, docs, and analytics; `/health` remains public. `SCANNER_CORS_ORIGINS` is an explicit comma-separated browser allowlist. An empty value allows no cross-origin browser access. CORS is separate from authentication. Place the dashboard behind authenticated access as well.

Compose binds API and dashboard ports to localhost. The image runs as UID 10001; make the `output/` and `.cache/` bind mounts writable by that UID. Back up generated reports, keep API instances single-worker until shared scan state is externalized, and enforce request limits at the reverse proxy. The inventory read limit is 10 MiB; multipart parsing may spool incoming data before the route checks it.

`/health` reports process liveness and current catalog state without contacting CISA. This prevents dependency outages from causing restart loops. Scanning still needs NVD/CISA access or an available cache; validate a sample scan separately. Keep the prior wheel/image for rollback and retain report/cache volumes.
