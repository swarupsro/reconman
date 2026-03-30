# Reconman

Reconman is a production-style Flask application for authorized internal Nmap assessments. It provides authenticated batch scanning, safe profile-based Nmap execution, Redis-backed background workers, live dashboard updates with Socket.IO, audit logging, scoped target validation, and CSV/JSON export.

## Features

- Flask app factory with Blueprint-based structure
- Login-protected internal operator dashboard
- Role-aware admin/operator access model
- Safe Nmap profile dropdown with a whitelist-only custom builder
- Batch orchestration with concurrency limits, pause, resume, stop, retry, and per-host timeouts
- Redis + RQ background processing so the web app stays responsive
- Real-time result updates with Flask-SocketIO
- SQLite development database with PostgreSQL-ready SQLAlchemy models
- Scan history with filtering by target, host state, port, service, profile, and time
- Raw output and XML output viewing per host
- CSV and JSON report export
- Audit logging for login and scan operations
- Dockerfile, `docker-compose.yml`, and sample seed data

## Project Layout

```text
app/
  __init__.py
  constants.py
  extensions.py
  forms.py
  models.py
  routes/
  services/
  static/
  tasks/
  templates/
  utils/
instance/
migrations/
scripts/
config.py
run.py
worker.py
requirements.txt
```

## Security Controls

- The UI never accepts raw Nmap command input.
- Profiles are expanded server-side from a strict whitelist.
- Targets are validated and must remain inside configured internal ranges.
- All launches and administrative changes are written to the audit log table.
- Rate limiting is enforced on login and scan submission routes.
- CSRF protection is enabled for form posts.

This tool must only be used for authorized internal security assessments.

## Quick Start

### 1. Local Python setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` and set a strong `SECRET_KEY` and admin password.

### 2. Start Redis

Use local Redis, Docker Desktop, or the bundled Compose stack.

### 3. Run the web app

```bash
python run.py
```

### 4. Run the RQ worker

In a second terminal:

```bash
python worker.py
```

### 5. Optional sample data

```bash
python scripts/seed.py
```

## Default Login

- Username: `admin`
- Password: value of `DEFAULT_ADMIN_PASSWORD`

Change it immediately in non-demo environments.

## Docker

```bash
docker compose up --build
```

The Compose stack starts:

- `web`: Flask + Socket.IO server
- `worker`: RQ worker for scan execution
- `redis`: queue, Socket.IO message bus, and rate-limit storage

## Nmap Notes

- Install Nmap on the host or use the Docker image.
- `SYN Scan (-sS)` is hidden by default unless `ENABLE_SYN_SCAN=true`.
- Some profiles such as OS detection or UDP scanning may require elevated privileges depending on the host OS and runtime environment.

## Main Pages

- `/login`
- `/`
- `/scans/new`
- `/scans/queue`
- `/scans/history`
- `/scans/<job_id>`
- `/settings`

## REST API Endpoints

- `GET /api/dashboard/stats`
- `GET /scans/api/batches/<batch_id>`
- `GET /scans/api/targets/<target_id>`
- `GET /scans/api/targets/<target_id>/output/raw`
- `GET /scans/api/targets/<target_id>/output/xml`

## Example Screenshots

- `[Placeholder] Login page screenshot`
- `[Placeholder] Dashboard screenshot`
- `[Placeholder] Job details screenshot`
- `[Placeholder] History/report screenshot`

## Extending Scan Profiles

Profiles live in `app/constants.py`. Add a new key with a label, description, and approved argument list, then optionally update the UI descriptions.

## Migration Path To PostgreSQL

- Set `DATABASE_URL` to a PostgreSQL connection string.
- Generate and apply real migrations with Flask-Migrate.
- Keep Redis for RQ and Socket.IO message delivery.

## Operational Caveats

- Pause stops new hosts from starting; already-running hosts are allowed to finish.
- Stop marks queued work as stopped and signals running hosts to terminate on the next polling interval.
- RQ does not preemptively cancel already-dequeued work, so stop responsiveness depends on the worker polling loop.
