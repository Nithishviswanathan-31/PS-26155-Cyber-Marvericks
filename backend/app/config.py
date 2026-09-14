from pathlib import Path
import os

import yaml

from .domain.schemas import ControlDefinition


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
DATABASE_PATH = BACKEND_ROOT / "demo.db"
CONTROLS_PATH = PROJECT_ROOT / "controls" / "demo_controls.yaml"


def is_demo_reset_enabled() -> bool:
    """Allow destructive demo reset only outside an explicit production environment."""

    app_env = os.getenv("APP_ENV", "development").strip().lower()
    requested = os.getenv("DEMO_RESET_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
    return requested and app_env not in {"production", "prod"}


def load_demo_controls(path: Path = CONTROLS_PATH) -> list[ControlDefinition]:
    """Load and validate the small P0.1 control catalogue."""

    with path.open("r", encoding="utf-8") as controls_file:
        document = yaml.safe_load(controls_file) or {}

    raw_controls = document.get("controls", [])
    return [ControlDefinition.model_validate(control) for control in raw_controls]
