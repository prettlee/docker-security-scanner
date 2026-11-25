# Docker Security Scanner

A Python-based security scanner to analyze Docker images (and containers) for insecure configurations, exposed secrets, and vulnerable dependencies.

## Phase 2 — Minimal Viable Scanner (Version 1)

Current Version 1 features:
- **Image/Container Metadata Parsing (`docker inspect`)**:
  - `user` (`Config.User`)
  - `exposed_ports` (`Config.ExposedPorts`)
  - `env` (`Config.Env`)
  - `entrypoint` (`Config.Entrypoint`)
  - `capabilities` (`HostConfig.CapAdd` / `HostConfig.CapDrop` when inspecting containers)
- **Root Container Detection (`DOCKER-001`)**:
  - Flags targets where `Config.User` is empty (`""`), `"root"`, or `"0"` (including `user:group` forms like `root:root` or `0:0`).

## Usage

Requires Python 3.9+ and the `docker` CLI (standard library only, no third-party dependencies).

```bash
# Scan an image (human-readable report)
python3 main.py nginx:latest

# Or run as a module
python3 -m scanner nginx:latest

# Output JSON
python3 main.py nginx:latest --json
```

Exit codes:
- `0`: No security findings
- `1`: One or more security findings detected
- `2`: Error running or parsing `docker inspect`

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
