# RUNBOOK

Bootstrapping this stack is a two-phase process: the BDOT Collector cannot
register with Bindplane until a Bindplane collector installation exists, and
that installation only gets created by hand in the Bindplane web UI. So
Phase 1 brings up everything *except* the collector, and Phase 2 is you,
in the browser.

## Phase 1 -- infrastructure

### 1. Configure `.env`

```bash
cp .env.example .env
```

Fill in every value in `.env` (see the group comments in `.env.example` for
what each one is for). In particular:

- Obtain a free Bindplane license key from https://bindplane.com/download
  and set `BINDPLANE_LICENSE`.
- Generate `BINDPLANE_SESSION_SECRET` and `KIBANA_ENCRYPTION_KEY` with
  `openssl rand -hex 32` (or similar).
- Leave `OPAMP_SECRET_KEY` blank for now -- it doesn't exist until Phase 2.

### 2. Bring up everything except the collector

```bash
docker compose up -d bindplane elasticsearch kibana_settings kibana litellm db prometheus langfuse-web langfuse-worker clickhouse minio redis postgres tracepump
```

`bdot-collector` is deliberately omitted: it depends on `bindplane`, and
without an `OPAMP_SECRET_KEY` yet, it would just start and immediately fail
to authenticate, over and over. That's expected and is what Phase 2 fixes.

### 3. Verify each service is healthy

```bash
docker compose ps
```

Expected `STATUS` column:

| Service | Expected status |
|---|---|
| `litellm` | `Up (healthy)` |
| `db` | `Up (healthy)` |
| `prometheus` | `Up` (no healthcheck defined) |
| `langfuse-web` | `Up` (no healthcheck defined) |
| `langfuse-worker` | `Up` (no healthcheck defined) |
| `clickhouse` | `Up (healthy)` |
| `minio` | `Up (healthy)` |
| `redis` | `Up (healthy)` |
| `postgres` | `Up (healthy)` |
| `bindplane` | `Up (healthy)` -- only once `BINDPLANE_LICENSE` is a real, valid license |
| `elasticsearch` | `Up (healthy)` |
| `kibana_settings` | `Exited (0)` -- this is a one-shot bootstrap job, not a long-running service |
| `kibana` | `Up (healthy)` |
| `tracepump` | `Up` (no healthcheck; see below) |

For any service reporting `unhealthy`, get details with:

```bash
docker inspect --format='{{json .State.Health}}' <container-name> | python3 -m json.tool
```

`tracepump` has no Docker healthcheck (it's a poller, not an HTTP service).
Confirm it's actually working by tailing its logs:

```bash
docker compose logs -f tracepump
```

You should see periodic `tracepump: poll ok, emitted N new trace(s)` lines
(every `TRACEPUMP_INTERVAL`, default 30s). Errors are logged as
`tracepump: poll failed: ... (retrying in ...)`.

## Phase 2 -- operator UI work

### 4. Log into Bindplane

Open http://localhost:3001 and log in with `BINDPLANE_USERNAME` /
`BINDPLANE_PASSWORD` from your `.env`.

### 5. Create a collector installation

On the **Agents** page, select **Install Agent** and choose the **Linux**
platform. Bindplane will show you a secret key and an OpAMP endpoint. Copy
the secret key into `.env` as `OPAMP_SECRET_KEY`.

(The OpAMP endpoint Bindplane shows you will likely reference
`app.bindplane.com` or similar -- ignore that and keep using
`ws://bindplane:3001/v1/opamp`, already set in `docker-compose.yml`, since
this collector talks to your local `bindplane` service, not Bindplane Cloud.)

### 6. Start the collector

```bash
docker compose up -d bdot-collector
```

Confirm it appears on Bindplane's **Agents** page as `bdot-collector`. It may
take a few seconds to show as connected after its first successful OpAMP
heartbeat.

### 7. Configure the pipeline (in the Bindplane UI)

The following is your work, not something this repo does for you -- the
constraint behind every task in this project was that Go code and compose
files only ever emit or carry *raw* data. Everything below is you shaping it
in the UI:

#### Create the LiteLLM source (OTLP receiver)

#### Create the Langfuse source (File receiver on `/data/langfuse-traces.ndjson`)

#### Add processors for ECS field mapping

#### Add the Elasticsearch destination

#### Roll out the configuration to the BDOT Collector

---

## Reference: LiteLLM container stdout as an alternative log source

LiteLLM's OTLP push (`OTEL_EXPORTER_OTLP_ENDPOINT` in `docker-compose.yml`)
sends **spans**. If you instead want LiteLLM's raw structured JSON stdout as
a **log** source in step 7 above, it's available via Docker's own JSON log
file rather than directly from the container.

The `litellm` service uses the `json-file` logging driver (`max-size: 10m`,
`max-file: 5`), so Docker persists its stdout on the host at:

```
/var/lib/docker/containers/<container-id>/<container-id>-json.log
```

Find the exact path for the running container:

```bash
container_id=$(docker compose ps -q litellm)
echo "/var/lib/docker/containers/${container_id}/${container_id}-json.log"
```

Each line in that file is a JSON object wrapping the container's stdout line
in Docker's own envelope (`{"log": "...", "stream": "stdout", "time": "..."}`),
not LiteLLM's JSON directly -- a File source and any processors need to
account for that extra layer.

To let `bdot-collector` read this file, the host's Docker log directory must
be mounted into it. That mount is present in `docker-compose.yml` on the
`bdot-collector` service, **commented out by default**:

```yaml
# - /var/lib/docker/containers:/var/lib/docker/containers:ro
```

Uncommenting it grants the collector read access to **every** container's
logs on this host, not just LiteLLM's. Only enable it if that's acceptable
for your environment.

## Port reference

Every host port this compose file claims, all bound to `127.0.0.1` only:

| Port | Service | Purpose |
|---|---|---|
| 3000 | `langfuse-web` | Langfuse UI / API |
| 3001 | `bindplane` | Web UI + OpAMP endpoint |
| 3002 | `bindplane` | Listed in Bindplane's docs' port requirements; unused by this single-node bbolt setup |
| 3030 | `langfuse-worker` | Langfuse background worker |
| 4000 | `litellm` | LiteLLM proxy (chat completions API) |
| 4317 | `bdot-collector` | OTLP gRPC receiver |
| 4318 | `bdot-collector` | OTLP HTTP receiver (LiteLLM's `OTEL_EXPORTER_OTLP_ENDPOINT` points here) |
| 5432 | `postgres` | Langfuse's Postgres |
| 5433 | `db` | LiteLLM's own Postgres (remapped from 5432, which Langfuse's Postgres holds) |
| 5601 | `kibana` | Kibana UI |
| 6379 | `redis` | Langfuse's Redis |
| 8123 | `clickhouse` | ClickHouse HTTP interface |
| 9000 | `clickhouse` | ClickHouse native protocol |
| 9090 | `minio` | MinIO S3 API (remapped from 9000, which ClickHouse holds) |
| 9091 | `minio` | MinIO console |
| 9092 | `prometheus` | Prometheus UI (remapped from 9090, which MinIO holds) |
| 9200 | `elasticsearch` | Elasticsearch HTTP API |
| 13133 | `bdot-collector` | Health check extension |

`tracepump` publishes no host port.

## Troubleshooting

### `bdot-collector` can't reach OpAMP

Symptoms: the container restart-loops; `docker compose logs bdot-collector`
shows connection refused/timeout or auth failures against
`ws://bindplane:3001/v1/opamp`.

- If `OPAMP_SECRET_KEY` is blank in `.env`, this is expected -- see Phase 2,
  steps 5-6.
- Confirm `bindplane` itself is healthy first (`docker compose ps`); the
  collector can't do anything useful until it is.
- Confirm the secret key in `.env` matches the one currently shown for this
  collector installation on Bindplane's Agents page -- it's invalidated if
  you delete and recreate the installation.
- Check connectivity directly from inside the collector container (it has
  no `curl`/`wget`, but does have `python3`):
  ```bash
  docker compose exec bdot-collector python3 -c "import urllib.request; print(urllib.request.urlopen('http://bindplane:3001').status)"
  ```
  A connection failure here means it's a networking/service-health problem,
  not a bad secret key.

### `tracepump` gets 401 from Langfuse

Symptoms: `docker compose logs tracepump` shows
`langfuse API returned status 401 Unauthorized`.

- `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` in `.env` must belong to an
  actual Langfuse project (create one via the Langfuse UI at
  http://localhost:3000 if you haven't, or via the
  `LANGFUSE_INIT_PROJECT_*` bootstrap variables).
- If you're relying on `LANGFUSE_INIT_PROJECT_PUBLIC_KEY`/`SECRET_KEY` to
  seed the project on first boot, remember those only take effect on
  Langfuse's *first ever* startup against an empty Postgres database --
  changing them after the fact does nothing. Set
  `LANGFUSE_PUBLIC_KEY`/`LANGFUSE_SECRET_KEY` to match whatever project
  actually exists.
- Confirm the keys work at all with a direct request:
  ```bash
  curl -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" http://localhost:3000/api/public/traces?limit=1
  ```

### `bdot-collector` can't reach Elasticsearch

This only becomes relevant once you've configured the Elasticsearch
destination in Phase 2, step 7.

- Elasticsearch has security enabled; the destination in the Bindplane UI
  needs real credentials (the `elastic` user and `ELASTIC_PASSWORD` from
  `.env`, or a dedicated API key you create for this purpose).
- Confirm Elasticsearch itself is healthy and reachable from inside the
  collector container (again via `python3`, replacing `PASSWORD_HERE` with
  your real `ELASTIC_PASSWORD`):
  ```bash
  docker compose exec bdot-collector python3 -c "
  import urllib.request, base64
  req = urllib.request.Request('http://elasticsearch:9200')
  req.add_header('Authorization', 'Basic ' + base64.b64encode(b'elastic:PASSWORD_HERE').decode())
  print(urllib.request.urlopen(req).status)
  "
  ```
- If that fails with a connection error rather than an auth error, check
  `docker compose ps elasticsearch` and `docker compose logs elasticsearch`
  first -- a still-starting or unhealthy Elasticsearch is the more common
  cause than a Bindplane misconfiguration.

## `docker compose down -v` warning

`-v` deletes every named volume, including data that is expensive or
impossible to regenerate. Before running it, know what you're giving up:

| Volume | Worth keeping? | Why |
|---|---|---|
| `langfuse_postgres_data` | **Yes** | Langfuse's projects, users, API keys, dashboards |
| `langfuse_clickhouse_data` | **Yes** | All Langfuse trace/observation history |
| `langfuse_minio_data` | **Yes** | Blob storage backing large trace payloads referenced by the above |
| `litellm_postgres_data` | **Yes** | LiteLLM's virtual keys, budgets, spend history |
| `bindplane_data` | **Yes** | Every source/processor/destination you configure by hand in Phase 2 |
| `bdot_collector_storage` | Usually | Collector's registration state (`manager.yaml`); losing it just means re-registering the collector in Phase 2 |
| `tracepump_data` | Usually | The NDJSON export and its checkpoint; losing it means tracepump re-emits Langfuse's full trace history on next boot -- harmless, just slower to catch up |
| `langfuse_clickhouse_logs` | No | ClickHouse's own operational logs |
| `langfuse_redis_data` | No | Langfuse's queue/cache, fully disposable |
| `prometheus_data` | No | LiteLLM's Prometheus metrics history, regenerates from new traffic |
| `elasticsearch_data` | Depends | Whatever you've indexed into Elasticsearch via the Bindplane pipeline -- keep if you've built detection rules or dashboards against it |
| `kibana_data` | Depends | Kibana's saved objects (data views, dashboards, detection rules) you build in step 7 -- keep if you've done that work |

If in doubt, use `docker compose down` (no `-v`) instead -- it stops and
removes containers but leaves every volume intact.
