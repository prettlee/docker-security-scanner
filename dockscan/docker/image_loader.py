"""Load Docker images into tar archives without ever executing the target image."""

from pathlib import Path
import shutil
import subprocess
from typing import Optional


class ImageLoadError(RuntimeError):
    """Raised when a Docker image archive cannot be loaded or saved."""


def _save_via_sdk(target: str, dest_tar: Path) -> bool:
    """Attempt to export an image using the Docker Python SDK if installed."""
    try:
        import docker  # type: ignore
    except ImportError:
        return False

    try:
        client = docker.from_env()
        image = client.images.get(target)
        with dest_tar.open("wb") as handle:
            for chunk in image.save(named=True):
                handle.write(chunk)
        return True
    except Exception as exc:  # pragma: no cover - depends on local SDK/daemon
        raise ImageLoadError(f"Docker SDK failed saving '{target}': {exc}") from exc


def _save_via_cli(target: str, dest_tar: Path) -> None:
    """Export an image using `docker image save` without running any container."""
    try:
        result = subprocess.run(
            ["docker", "image", "save", "-o", str(dest_tar), target],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ImageLoadError("Docker CLI ('docker') was not found in PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ImageLoadError(f"`docker image save` timed out for '{target}'.") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or f"exit code {result.returncode}"
        raise ImageLoadError(f"`docker image save {target}` failed: {stderr}")


def load_image_tar(
    target: str,
    dest_dir: Path,
    prefer_sdk: bool = True,
) -> Path:
    """Return a path to a Docker image tar archive for `target`.

    If `target` points to an existing `.tar` file on disk, it is returned directly.
    Otherwise, exports the image using the Docker SDK if available or
    `docker image save`. Never executes the target image.
    """
    local_path = Path(target)
    if local_path.is_file():
        return local_path

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_tar = dest_dir / "image.tar"

    if prefer_sdk and _save_via_sdk(target, dest_tar):
        return dest_tar

    _save_via_cli(target, dest_tar)
    return dest_tar


def cleanup_temp_tar(temp_dir: Optional[Path]) -> None:
    """Remove temporary directory created during image export."""
    if temp_dir is not None and temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)
