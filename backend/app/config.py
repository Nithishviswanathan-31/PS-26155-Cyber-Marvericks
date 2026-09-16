from pathlib import Path
import os

import yaml
from pydantic import ValidationError

from .domain.schemas import ControlDefinition
from .domain.properties import valid_property_value


class CatalogueError(ValueError):
    """Configuration failure distinct from an intentionally disabled selection."""

    error_code = "INVALID_CATALOGUE"

    def __init__(self, message: str):
        super().__init__(message)
        self.detail = message


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
# The default remains the local demo database. Validation and offline operators
# may select an isolated SQLite file before the process starts.
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BACKEND_ROOT / "demo.db"))).resolve()
CONTROLS_PATH = PROJECT_ROOT / "controls" / "demo_controls.yaml"
BATCH_MAX_FILES = 25
BATCH_MAX_FILE_BYTES = 1 * 1024 * 1024
BATCH_MAX_TOTAL_BYTES = 10 * 1024 * 1024
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").lower() in {"1", "true", "yes"}
AUTH_SECRET = os.getenv("AUTH_SECRET", "")
AUTH_TTL_SECONDS = int(os.getenv("AUTH_TTL_SECONDS", "3600"))


def is_demo_reset_enabled() -> bool:
    """Allow destructive demo reset only outside an explicit production environment."""

    app_env = os.getenv("APP_ENV", "development").strip().lower()
    requested = os.getenv("DEMO_RESET_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
    return requested and app_env not in {"production", "prod"}


def load_demo_controls(path: Path = CONTROLS_PATH) -> list[ControlDefinition]:
    """Validate the catalogue, then select enabled controls in catalogue order.

    Vendor and framework metadata never filter or change evaluation.
    """

    try:
        with path.open("r", encoding="utf-8") as controls_file:
            document = yaml.safe_load(controls_file)
        if not isinstance(document, dict) or set(document) != {"controls"}:
            raise CatalogueError("Catalogue must contain the required controls key only.")
        raw_controls = document["controls"]
        if not isinstance(raw_controls, list) or not raw_controls:
            raise CatalogueError("controls must be a nonempty list; use enabled: false for intentional disabling.")
        controls = [ControlDefinition.model_validate(control) for control in raw_controls]
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise CatalogueError(f"Invalid control catalogue: {exc}") from exc
    if len({control.control_id for control in controls}) != len(controls):
        raise CatalogueError("control IDs must be unique")
    from .services.remediation_service import validate_remediation_reference

    by_id = {control.control_id: control for control in controls}
    for control in controls:
        if not control.control_id.strip() or control.control_id != control.control_id.strip():
            raise CatalogueError("Control IDs must be nonblank and have no surrounding whitespace.")
        for condition in control.evaluation.conditions:
            if not valid_property_value(condition.path, condition.expected):
                raise CatalogueError(f"{control.control_id}: unregistered property or invalid expected type: {condition.path}")
        for vendor, reference in (control.remediation_reference or {}).items():
            if not validate_remediation_reference(vendor, control.control_id, reference):
                raise CatalogueError(f"{control.control_id}: invalid remediation reference {vendor}/{reference}")
        if control.diagnostic_of:
            parent = by_id.get(control.diagnostic_of)
            if parent is None or parent is control or parent.diagnostic_of:
                raise CatalogueError(f"{control.control_id}: diagnostic parent must be an existing root control")
            if control.enabled and not parent.enabled:
                raise CatalogueError(f"{control.control_id}: enabled diagnostic requires enabled parent")
            if not control.evaluation.conditions or any(c not in parent.evaluation.conditions for c in control.evaluation.conditions):
                raise CatalogueError(f"{control.control_id}: diagnostic conditions must belong to the parent")
    return [control for control in controls if control.enabled]
