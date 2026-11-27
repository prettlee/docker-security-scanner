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
   - **Unified Reporting (Phase 5)**: aggregates secrets, configuration checks, and optional CVE findings with severity classification (`Critical`, `High`, `Medium`, `Low`), numeric confidence scoring (`0.00–1.00`), redacted terminal output, structured JSON reports, and a self-contained interactive **HTML dashboard** (`--html`)
3. **`dockscan/dockerfile/` (Phase 6 — Static Dockerfile Security Analysis)**
   - Analyzes Dockerfiles independently from built images (handling line continuations and multi-stage builds)
   - Detects `:latest`/untagged `FROM` images, missing non-root `USER`, hardcoded credentials, unsafe `ADD` instructions, unpinned `pip`/`npm`/`apt`/`apk` dependencies, insecure `RUN` install commands (`curl|sh`, disabled TLS/signature verification, `http://`, `chmod 777`), and missing `HEALTHCHECK`
4. **GitHub Action CI/CD Integration (`action.yml` & `.github/workflows/ci.yml`)**
   - Reusable composite GitHub Action with configurable `fail-on` severity threshold, JSON report output, step outputs (`total-findings`, `critical-count`, etc.), and automatic `$GITHUB_STEP_SUMMARY` Markdown reports

## Usage

### GitHub Action (CI/CD)

```yaml
- name: Scan Docker image
  uses: prettlee/docker-security-scanner@main
  with:
    target: my-app:latest
    scan-type: image
    with-vulns: "true"
    fail-on: high
    output-file: dockscan-report.json
```

Or scan a Dockerfile in CI:

```yaml
- name: Scan Dockerfile
  uses: prettlee/docker-security-scanner@main
  with:
    target: ./Dockerfile
    scan-type: dockerfile
    fail-on: high
```

### Phase 6: Static Dockerfile Analysis

```bash
python3 -m dockscan.dockerfile ./Dockerfile
python3 -m dockscan --dockerfile ./Dockerfile --json --output dockerfile-report.json --html dockerfile-report.html
```

### Phases 4 & 5: Built Image Security & Secret Report

```bash
python3 -m dockscan my-app:latest
python3 -m dockscan my-app:latest --with-vulns --fail-on high --html dashboard.html
python3 -m dockscan ./image.tar --json --output security-report.json
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
