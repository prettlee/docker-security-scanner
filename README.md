# Docker Security Scanner

A Python-based security scanner to analyze Dockerfiles, Docker images, and containers for insecure configurations, exposed secrets, and vulnerable dependencies.

## Capabilities

1. **`scanner/` (Phases 2 & 3 — Config & Package Vulnerability Scanning)**
   - Metadata inspection via `docker inspect` (root user, dangerous ports, suspicious env vars)
   - Installed package extraction (`apt`, `apk`, `pip`, `npm`) and CVE lookup via the **OSV.dev** `/v1/querybatch` API
2. **`dockscan/` (Phases 4 & 5 — Static Image Secret Scanning & Unified Security Reporting)**
   - **Never executes the target image** during secret/config scanning: exports via Docker SDK or `docker image save` (or reads a `.tar` archive directly) and parses layers with Python `tarfile`
   - Scans individual layers (including files deleted in later layers) for text files up to 10 MB
   - Combines regex + contextual rules, Shannon entropy analysis, and image metadata scanning (`ENV`, `LABEL`, build `history`)
   - **Unified Reporting (Phase 5)**: aggregates secrets, configuration checks, and optional CVE findings with severity classification (`Critical`, `High`, `Medium`, `Low`), numeric confidence scoring (`0.00–1.00`), redacted terminal output, and structured JSON reports
3. **`dockscan/dockerfile/` (Phase 6 — Static Dockerfile Security Analysis)**
   - Analyzes Dockerfiles independently from built images (handling line continuations and multi-stage builds)
   - Detects `:latest`/untagged `FROM` images, missing non-root `USER`, hardcoded credentials, unsafe `ADD` instructions, unpinned `pip`/`npm`/`apt`/`apk` dependencies, insecure `RUN` install commands (`curl|sh`, disabled TLS/signature verification, `http://`, `chmod 777`), and missing `HEALTHCHECK`

## Project Architecture (`dockscan/`)

```text
dockscan/
├── __init__.py
├── __main__.py
├── scanner.py
├── dockerfile/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── parser.py
│   ├── analyzer.py
│   └── security_checks.py
├── docker/
│   ├── image_loader.py
│   ├── layer_extractor.py
│   └── metadata.py
├── secrets/
│   ├── filesystem_scanner.py
│   ├── metadata_scanner.py
│   ├── pattern_detector.py
│   ├── entropy_detector.py
│   ├── rules.py
│   └── aggregator.py
├── reporting/
│   ├── aggregator.py
│   ├── scoring.py
│   ├── terminal.py
│   └── json_report.py
├── models/
│   └── finding.py
└── tests/
    ├── fixtures/
    │   ├── Dockerfile.insecure
    │   └── Dockerfile.vulnerable
    ├── test_layer_extraction.py
    ├── test_pattern_detector.py
    ├── test_entropy_and_filesystem.py
    ├── test_metadata_scanner.py
    ├── test_reporting.py
    ├── test_dockerfile_parser.py
    ├── test_dockerfile_structure_checks.py
    ├── test_dockerfile_security_checks.py
    ├── test_dockerfile_cli.py
    └── test_end_to_end.py
```

## Usage

### Phase 6: Static Dockerfile Analysis

```bash
# Standalone Dockerfile analyzer
python3 -m dockscan.dockerfile ./Dockerfile

# Or via dockscan --dockerfile
python3 -m dockscan --dockerfile ./Dockerfile --json --output dockerfile-report.json
```

### Phases 4 & 5: Built Image Security & Secret Report

```bash
# Static scan (secrets + image configuration checks; never runs the image)
python3 -m dockscan my-app:latest

# Include package extraction & OSV.dev CVE scanning
python3 -m dockscan my-app:latest --with-vulns

# Secret scanning only
python3 -m dockscan my-app:latest --secrets-only

# Scan a saved Docker image tarball
python3 -m dockscan ./image.tar

# Output JSON and save report
python3 -m dockscan my-app:latest --json --output security-report.json
```

### Phases 2 & 3 Scanner (`scanner`)

```bash
python3 main.py nginx:latest
python3 main.py nginx:latest --no-vuln --json
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s dockscan/tests -v
```
