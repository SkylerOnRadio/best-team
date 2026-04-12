<div align="center">
  <img src="https://img.icons8.com/fluency/96/cyber-security.png" alt="Cyber Security" width="78" height="78" />
  <h1>Log Detector and Foreign Threat Analysis</h1>
  <p><strong>Evidence-first log forensics, risk intelligence, and real-time investigation workflow</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-Forensic%20Engine-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/Flask-API-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
    <img src="https://img.shields.io/badge/Socket.IO-Real--Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white" alt="SocketIO" />
    <img src="https://img.shields.io/badge/React-Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0A192F" alt="React" />
    <img src="https://img.shields.io/badge/TypeScript-Strongly%20Typed-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  </p>
</div>

---

A full-stack cybersecurity monitoring platform that analyzes log files for timeline tampering, suspicious actor behavior, coordinated attacks, and advanced threat signals.

## Quick Navigation

| Section                 | Focus                               |
| ----------------------- | ----------------------------------- |
| Executive Summary       | Strategic overview and mission      |
| Our USP                 | Unique product differentiation      |
| Architecture Overview   | End-to-end technical design         |
| Key Features            | Engine, APIs, reporting, dashboard  |
| Deep Technical Analysis | Risk model and enrichment internals |
| Setup and Run           | Local environment and launch flow   |
| API Quick Reference     | Endpoint-level integration summary  |
| Roadmap Snapshot        | Forward engineering direction       |

## Executive Summary

This project delivers a practical Security Analytics + Forensics platform for teams that need more than basic log search.
It transforms raw logs into prioritized investigative intelligence through:

- deterministic anomaly detection,
- threat actor behavior profiling,
- interpretable risk scoring,
- and report-grade artifact generation.

The result is a system that supports both fast incident triage and evidence-oriented post-incident analysis.

## Our USP (Unique Selling Proposition)

Most tools either stop at visualization or produce black-box scores. This platform is different.

- Evidence-first risk intelligence: Every score is backed by traceable gaps, tags, sessions, and artifacts.
- Dual-mode operations in one stack: Real-time periodic monitoring plus analyst-triggered manual scans.
- Analyst-ready outputs by default: JSON + CSV + HTML reports are generated automatically for audit and sharing.
- Kill-chain-aware scoring model: Risk rises with attack progression depth, not just event volume.
- Practical deployment posture: Works with standard Python + React stack and supports Windows/Linux workflows.

In short: it is not only a dashboard, it is a reproducible forensic decision system.

The project combines:

- A Python forensic engine ([log.py](log.py)) for deep log analysis and report generation
- A Flask + Socket.IO API service ([backend.py](backend.py)) for manual and scheduled scans
- A React + TypeScript dashboard ([frontend/src/App.tsx](frontend/src/App.tsx)) for investigation workflows

## Technology Logos

<div align="center">
  <img src="https://cdn.simpleicons.org/python/3776AB" alt="Python" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/flask/000000" alt="Flask" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/socketdotio/010101" alt="Socket.IO" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/react/61DAFB" alt="React" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/typescript/3178C6" alt="TypeScript" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/tailwindcss/06B6D4" alt="Tailwind CSS" width="38" height="38" />
  &nbsp;&nbsp;
  <img src="https://cdn.simpleicons.org/vite/646CFF" alt="Vite" width="38" height="38" />
</div>

## Platform Snapshot

| Layer              | Core Responsibility                          | Primary File                                                     |
| ------------------ | -------------------------------------------- | ---------------------------------------------------------------- |
| Detection Engine   | Parse, enrich, correlate, score threats      | [log.py](log.py)                                                 |
| API + Scheduler    | Serve scans, stream updates, archive results | [backend.py](backend.py)                                         |
| UI Experience      | Investigation workflow and visual analytics  | [frontend/src/App.tsx](frontend/src/App.tsx)                     |
| Packaging Scaffold | CLI packaging/build support                  | [log_checker_cli/pyproject.toml](log_checker_cli/pyproject.toml) |

## Business and Security Value

- Faster incident response: Security teams can identify high-risk windows and actor clusters quickly.
- Better prioritization: Zone-based compromise probabilities prevent alert fatigue and support triage decisions.
- Auditability: Generated artifacts preserve evidence trails for internal reviews and compliance workflows.
- Extensibility: Signature logic, IOC feeds, and reporting layers can be extended without replacing the whole stack.

## Ideal Use Cases

- SOC lab and blue-team exercises
- Internal threat-hunting pipelines
- Security engineering capstone/demo environments
- Compliance-oriented log review where report exports are mandatory

## Why This Project Exists

Traditional log viewers show events. This platform focuses on **forensic risk interpretation**:

- Detect missing or reversed time segments in logs
- Identify brute force bursts, distributed login storms, suspicious payload entropy, and kill-chain progression
- Compute zone-based risk probabilities and collapse them into a single risk score
- Preserve artifacts (JSON, CSV, HTML) for analyst review and audit history

## Architecture Overview

```text
Upload/System Log ---> backend.py ---> log.py analysis engine ---> results (dict)
       |                 |                    |                       |
       |                 |                    |                       +--> terminal report
       |                 |                    +--> risk zones + threats + gaps
       |                 +--> JSON/CSV/HTML artifacts
       +--> frontend fetch + websocket <------+
```

    ### Architecture At A Glance

    | Input | Processing | Output |
    |---|---|---|
    | Manual upload or system log source | Timestamp integrity checks + threat signature pipeline + risk-zone computation | Live dashboard signals + archived JSON/CSV/HTML forensic artifacts |

### Runtime components

- Forensic engine: [log.py](log.py)
- API + scheduler + websocket server: [backend.py](backend.py)
- Dashboard client: [frontend/src/App.tsx](frontend/src/App.tsx)
- Optional CLI packaging scaffold: [log_checker_cli/pyproject.toml](log_checker_cli/pyproject.toml)

### Data Flow (Investigation Lifecycle)

1. Logs enter through scheduled system scan or manual upload.
2. The engine parses timeline and behavioral features in a single-pass + enrichment pipeline.
3. Risk zones and aggregate risk score are computed.
4. Results are exposed via API/websocket and persisted as forensic artifacts.
5. Investigators consume live and historical findings in the dashboard.

## Key Features

### 1. Advanced log forensics (engine)

Implemented in [log.py](log.py):

- Multi-format timestamp parsing
- Gap and reversed-timeline detection
- Signature-based threat tagging (failed login, privilege escalation, exfiltration, lateral movement, etc.)
- Brute-force burst and distributed attack window detection
- IOC feed support (`--ioc-feed`)
- Session reconstruction per actor
- Entropy-baseline calibration and high-entropy payload detection
- Kill-chain stage scoring and confirmation
- Zone-based compromise probabilities and aggregate risk scoring

### 2. Report artifact generation

Generated by [log.py](log.py) and orchestrated by [backend.py](backend.py):

- JSON forensic snapshots
- CSV integrity reports
- CSV behavioral/threat actor reports
- HTML visual forensic report

Default artifact root:

- `~/Documents/Forensic_Reports/`

Subfolders used:

- `json/` (periodic report history grouped by date)
- `csv/` (integrity + behavioral CSV)
- `html/` (visual reports)
- `manual-scans/` (manual scan JSON cache; cleaned after 24h)

### 3. API-driven operations

Endpoints in [backend.py](backend.py):

- `GET /api/health` health and active log information
- `POST /api/analyze/manual` upload + threshold based manual scan
- `GET /api/reports` list periodic reports grouped by date
- `GET /api/reports/<date>/<filename>` retrieve a specific periodic report payload

### 4. Real-time dashboard

Implemented in [frontend/src/App.tsx](frontend/src/App.tsx):

- Manual scan upload flow (file + threshold)
- Calendar-driven replay of periodic reports
- WebSocket live updates (`new_forensic_data`, `scan_error`)
- Risk meter, metrics, anomaly tables, actor analysis, timeline/bubble charts
- Environment-configurable backend URL via `VITE_API_URL`

## Deep Technical Analysis

### Risk model design

The engine computes per-zone probabilities (`integrity`, `access`, `persistence`, `privacy`, `continuity`, `exfiltration`, `lateral`) then combines them with an independent-zone saturation model:

- `P(compromise) = 1 - Π(1 - P(zone_i))`

This model avoids all-or-nothing scoring and allows independent evidence channels to contribute proportionally.

### Signal enrichment strategy

The pipeline intentionally stages analysis:

1. Baseline pass for entropy threshold calibration
2. Main linear scan for timestamps, templates, IP events, signatures
3. Post-pass enrichment for brute-force windows, distributed attack correlation, kill-chain scoring, session reconstruction
4. Cross-cutting confidence boosts (IOC hits, kill-chain depth, entropy events)

This staged approach balances throughput and analytical depth.

### Operational behavior

- A background scanner runs every `SCAN_INTERVAL` seconds (default 3600) in [backend.py](backend.py)
- It scans the first readable target from `SYSTEM_LOGS`
- On success it persists report artifacts and emits websocket updates
- On error it emits a `scan_error` event
- Manual uploads are analyzed immediately and temporary JSON artifacts older than 24h are deleted

### Frontend resilience

The dashboard normalizes incoming payloads before rendering in [frontend/src/App.tsx](frontend/src/App.tsx), allowing it to remain stable across partial backend schema changes and missing fields.

## Professional Operations Notes

### Performance profile

- Core parsing is designed around linear scan behavior with targeted post-pass enrichment.
- Runtime metrics (`time`, `lps`) are captured and exposed for operational visibility.

### Report governance

- Periodic reports are date-grouped for straightforward historical replay.
- Manual scan caches are auto-pruned after 24 hours to limit stale storage growth.

### Platform scope

- Backend monitoring targets standard Linux log locations with local fallback support.
- Frontend remains endpoint-driven and can be redirected through `VITE_API_URL` for staging/production setups.

## Repository Structure

```text
best-team/
  backend.py
  log.py
  log_checker.py
  log_checker_2.py
  log_checker_3.py
  requirements.txt
  frontend/
    package.json
    src/
      App.tsx
      components/
      types.ts
  log_checker_cli/
    pyproject.toml
```

## Setup and Run

> [!TIP]
> For best stability on Windows, run backend and frontend in separate terminals and keep the backend terminal active for scheduler + websocket events.

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm 9+

## 1) Backend setup

From repository root:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start backend:

```powershell
python backend.py
```

Optional: force an initial scan against a specific file on startup:

```powershell
python backend.py sample.log
```

Backend default URL:

- `http://127.0.0.1:5000`

## 2) Frontend setup

In [frontend](frontend):

```powershell
npm install
npm run dev
```

Optional `.env` for API base URL:

```bash
VITE_API_URL=http://127.0.0.1:5000
```

Frontend default URL (Vite):

- `http://127.0.0.1:5173`

## API Quick Reference

| Endpoint                         | Method | Purpose                                       |
| -------------------------------- | ------ | --------------------------------------------- |
| `/api/health`                    | GET    | Runtime health and active periodic log source |
| `/api/analyze/manual`            | POST   | On-demand manual scan via uploaded log        |
| `/api/reports`                   | GET    | Date-grouped list of periodic reports         |
| `/api/reports/<date>/<filename>` | GET    | Fetch a specific archived periodic report     |

### `GET /api/health`

Returns runtime status and active periodic source log.

### `POST /api/analyze/manual`

Form-data:

- `file`: log file
- `threshold`: gap threshold in seconds (optional)

Returns forensic payload including:

- `gaps`
- `threats`
- `risk_score`
- `performance`
- `stats`
- `artifact_paths`

### `GET /api/reports`

Returns date-grouped list of periodic report JSON files.

### `GET /api/reports/<date>/<filename>`

Returns one stored periodic report payload.

## CLI Engine Usage

You can also run the core engine directly:

```powershell
python log.py sample.log --threshold 120 --format all
```

Additional useful options:

- `--ioc-feed <path>` include known-bad IP list
- `--compare <path>` compare against a second log
- `--format terminal|json|csv|html|all`

## Security and Reliability Notes

- Uploads are written to secure temporary files and removed after analysis in [backend.py](backend.py)
- Manual scan JSON cache is pruned for files older than 24 hours
- Date/filename route params are sanitized using basename before file access
- CORS is enabled for cross-origin dashboard development

## Known Gaps and Improvement Opportunities

- `requirements.txt` currently includes both Flask and FastAPI stacks; only Flask is used by [backend.py](backend.py)
- Schema alignment can be tightened between backend payload keys and frontend type contracts in [frontend/src/types.ts](frontend/src/types.ts)
- No test suite exists yet for engine, API, or frontend components
- Authentication/authorization is not enabled for API endpoints
- Production deployment profile (reverse proxy, TLS, worker model) is not yet documented in code

## Roadmap Snapshot

- Versioned API contracts and strict schema validation
- RBAC + authentication for multi-user operations
- Containerized production deployment blueprint
- Configurable retention and archival policy controls
- Test coverage baseline across engine, API, and frontend layers

## Suggested Next Engineering Steps

1. Add automated tests:
   - Unit tests for risk-zone calculation and parsers in [log.py](log.py)
   - API contract tests for [backend.py](backend.py)
   - Component/integration tests for [frontend/src/App.tsx](frontend/src/App.tsx)
2. Introduce typed API contracts (OpenAPI + generated frontend types)
3. Add auth and role-based access to report APIs
4. Add production-ready deployment files (Docker, process manager, Nginx)
5. Add retention policy configuration for periodic artifact folders

## License

No license file is currently present in this repository. Add one before distribution.
