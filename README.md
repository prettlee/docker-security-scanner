# Docker Security Scanner

A Python-based security scanner to analyze Docker images and containers for insecure configurations, exposed secrets, and vulnerable dependencies.

## Modules

1. **`scanner/` (Phases 2 & 3 — Config & Package Vulnerability Scanning)**
   - Metadata inspection via `docker inspect` (root user, dangerous ports, suspicious env vars)
   - Installed package extraction (`apt`, `apk`, `pip`, `npm`) and CVE lookup via the **OSV.dev** `/v1/querybatch` API
2. **`dockscan/` (Phase 4 — Static Image Layer & Metadata Secret Scanning)**
   - **Never executes the target image**: exports via Docker SDK or `docker image save` (or reads a `.tar` archive directly) and parses layers with Python `tarfile`
   - Scans individual layers (including files deleted in later layers) for text files up to 10 MB
   - Combines regex + contextual rules, Shannon entropy analysis, and image metadata scanning (`ENV`, `LABEL`, build `history`)
   - Separates **Severity** (`Critical`, `High`, `Medium`, `Low`) from **Confidence** (`High`, `Medium`, `Low`) and always redacts matched secrets

## Phase 4 Architecture (`dockscan/`)

```text
dockscan/
├── __init__.py
├── __main__.py
├── scanner.py
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
│   ├── terminal.py
│   └── json_report.py
├── models/
│   └── finding.py
└── tests/
    ├── fixtures/
    │   └── Dockerfile.vulnerable
    ├── test_layer_extraction.py
    ├── test_pattern_detector.py
    ├── test_entropy_and_filesystem.py
    ├── test_metadata_scanner.py
    └── test_end_to_end.py
```

## Usage

### Phase 4 Secret Scanner (`dockscan`)

```bash
# Scan a local Docker image statically (never runs the image)
python3 -m dockscan my-image:latest

# Scan a saved Docker image tarball
python3 -m dockscan ./image.tar

# Output JSON and save report
python3 -m dockscan my-image:latest --json --output secrets-report.json
```

### Phase 2 & 3 Scanner (`scanner`)

```bash
python3 main.py nginx:latest
python3 main.py nginx:latest --no-vuln --json
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s dockscan/tests -v
```
