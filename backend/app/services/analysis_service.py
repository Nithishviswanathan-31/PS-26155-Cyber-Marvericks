import logging
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ..config import CatalogueError, load_demo_controls
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.control_engine import DeterministicControlEngine
from ..domain.evidence import build_evidence
from ..domain.schemas import AnalysisDeviceResponse, AnalysisResponse, ControlResultSummary
from ..parsers.astranet import AstraNetParser
from ..parsers.cisco import CiscoParser
from ..parsers.fortigate import FortiGateParser
from ..parsers.paloalto import PaloAltoParser
from ..services.inventory_service import prepare_inventory
from ..storage.database import get_device, save_analysis_result

logger = logging.getLogger(__name__)


def analyze_configuration_bytes(content: bytes, filename: str, device_id: str | None = None, controls=None, actor_id: str | None = None) -> AnalysisResponse:
    """Run the canonical single-configuration analysis pipeline."""
    filename = Path(filename).name
    if not filename:
        raise ApiError(400, ApiErrorCode.UNSUPPORTED_INPUT, "A configuration filename is required.")
    if Path(filename).suffix.lower() not in {".conf", ".cfg", ".txt"}:
        raise ApiError(400, ApiErrorCode.UNSUPPORTED_INPUT, "Unsupported file type. Use a .conf, .cfg, or .txt configuration file.")
    if not content:
        raise ApiError(400, ApiErrorCode.MALFORMED_CONFIGURATION, "The uploaded configuration file is empty.")
    if len(content) > 1 * 1024 * 1024:
        raise ApiError(400, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration file exceeds the 1 MB demo limit.")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(400, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration file must be UTF-8 text.") from exc

    parser = next((candidate for candidate in (CiscoParser, FortiGateParser, PaloAltoParser, AstraNetParser) if candidate.detect(text)), None)
    if parser is None:
        raise ApiError(400, ApiErrorCode.UNSUPPORTED_INPUT, "Unsupported configuration input. The demo supports Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and fictional AstraNet synthetic configurations.")
    try:
        security_ir = parser.parse(text, source_file=filename)
    except (TypeError, ValueError) as exc:
        raise ApiError(400, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration could not be parsed safely.") from exc

    signature = sha256(content).hexdigest()
    for pattern in security_ir.unknown_patterns:
        pattern.pattern_id = f"{pattern.pattern_id}-{signature}"
    controls = controls if controls is not None else load_demo_controls()
    existing_device = get_device(device_id) if device_id else None
    if device_id and existing_device is None:
        raise ApiError(404, ApiErrorCode.DEVICE_NOT_FOUND, "Selected device was not found.")
    try:
        device_record, configuration = prepare_inventory(security_ir, filename, signature, existing_device)
    except ValueError as exc:
        raise ApiError(400, ApiErrorCode.UNSUPPORTED_INPUT, str(exc)) from exc
    security_ir.device.device_id = device_record.device_id
    evaluations = DeterministicControlEngine().evaluate_all(security_ir, controls)
    response = AnalysisResponse(
        analysis_id=str(uuid4()), filename=filename, vendor=security_ir.device.vendor,
        configuration=configuration,
        device=AnalysisDeviceResponse(
            hostname=security_ir.device.hostname, version=security_ir.device.version,
            device_model=security_ir.device.device_model, platform=security_ir.device.platform,
            serial_number=security_ir.device.serial_number, device_id=security_ir.device.device_id,
        ),
        results=[ControlResultSummary(
            control_id=e.control_id, control_name=e.control_name,
            diagnostic_of=next(c.diagnostic_of for c in controls if c.control_id == e.control_id),
            result=e.result, expected=e.expected, actual=e.actual, explanation=e.explanation,
            severity=e.severity, category=e.category, framework_mappings=e.framework_mappings,
        ) for e in evaluations],
        evidence=[item for e in evaluations for item in build_evidence(security_ir, e)],
        unknown_patterns=security_ir.unknown_patterns,
    )
    try:
        save_analysis_result(
            analysis_id=response.analysis_id, filename=filename, vendor=security_ir.device.vendor,
            response=response.model_dump(mode="json"), security_ir=security_ir.model_dump(mode="json"),
            device_record=device_record, configuration_record=response.configuration, actor_id=actor_id,
        )
    except Exception as exc:
        logger.exception("Could not persist analysis result %s", response.analysis_id)
        raise ApiError(500, ApiErrorCode.STORAGE_FAILURE, "The analysis could not be stored.") from exc
    return response
