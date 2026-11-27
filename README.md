# Docker Security Scanner

A Python-based security scanner to analyze Docker images and containers for insecure configurations, exposed secrets, and vulnerable dependencies.

## Features

### Phase 2 — Configuration & Secret Checks
1. **Image/Container Metadata Parsing (`docker inspect`)**:
   - `user` (`Config.User`)
   - `exposed_ports` (`Config.ExposedPorts`) and `port_bindings` (`HostConfig.PortBindings`)
   - `env` (`Config.Env`)
   - `entrypoint` (`Config.Entrypoint`)
   - `capabilities` (`HostConfig.CapAdd` / `HostConfig.CapDrop` when inspecting containers)
2. **Root Container Detection (`DOCKER-001`)**:
   - Flags targets where `Config.User` is empty (`""`), `"root"`, or `"0"` (including `user:group` forms like `root:root` or `0:0`).
3. **Dangerous Port Detection (`DOCKER-002`)**:
   - Flags SSH (`22`), unencrypted Docker daemon API (`2375`), and publicly exposed database ports (`1433`, `1521`, `3306`, `5432`, `5984`, `6379`, `9042`, `9200`, `9300`, `11211`, `27017`).
   - Distinguishes container `HostConfig.PortBindings` bound to `127.0.0.1` vs public interfaces (`0.0.0.0` / `::` / `""`).
4. **Suspicious Environment Variables (`DOCKER-003`)**:
   - Scans `Config.Env` keys for `API_KEY`, `SECRET`, `PASSWORD`, and `TOKEN` (case-insensitive) and redacts secret values in reports and evidence.

### Phase 3 — Vulnerability Scanning (OSV.dev Batch API)
5. **Installed Package Extraction**:
   - Extracts installed `apt` (`Debian`/`Ubuntu`), `apk` (`Alpine`), `pip` (`PyPI`), and global `npm` packages from images (`docker run --rm --entrypoint /bin/sh`) or running containers (`docker exec`).
6. **OSV.dev Vulnerability Lookup (`DOCKER-004`)**:
   - Batch-queries `https://api.osv.dev/v1/querybatch` (with pagination support) and fetches vulnerability summaries, CVE aliases, severity, and fixed versions from `GET /v1/vulns/{id}`.

## Project Architecture

```text
scanner/
├── __init__.py
├── __main__.py
├── cli.py
├── models.py
├── scanner.py
├── checks/
│   ├── __init__.py
│   ├── root_check.py
│   ├── ports_check.py
│   ├── env_check.py
│   └── vuln_check.py
├── utils/
│   ├── __init__.py
│   ├── docker.py
│   ├── packages.py
│   └── osv.py
└── reports/
    ├── __init__.py
    └── formatter.py
```

## Usage

Requires Python 3.9+ and the `docker` CLI (standard library only, no third-party dependencies).

```bash
# Full scan (configuration checks + package vulnerability scan)
python3 main.py nginx:latest

# Or run as a module
python3 -m scanner nginx:latest

# Skip package extraction / OSV.dev lookup (offline mode)
python3 main.py nginx:latest --no-vuln

# Output JSON
python3 main.py nginx:latest --json

# Save report to a file
python3 main.py nginx:latest --json --output report.json
```

Exit codes:
- `0`: No security findings
- `1`: One or more security findings detected
- `2`: Error running or parsing `docker inspect`

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
