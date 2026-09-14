import logging
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, UploadFile, status

from ..config import load_demo_controls
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.control_engine import DeterministicControlEngine
from ..domain.evidence import build_evidence
from ..domain.schemas import (
    AnalysisDeviceResponse,
    AnalysisResponse,
    ControlResultSummary,
)
from ..parsers.cisco import CiscoParser
from ..parsers.fortigate import FortiGateParser
from ..parsers.paloalto import PaloAltoParser
from ..parsers.astranet import AstraNetParser
from ..storage.database import save_analysis_result


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analysis"])

MAX_CONFIGURATION_BYTES = 1 * 1024 * 1024
ALLOWED_CONFIGURATION_SUFFIXES = {".conf", ".cfg", ".txt"}


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_configuration(file: UploadFile = File(...)) -> AnalysisResponse:
    """Analyze one supported real-vendor or synthetic AstraNet configuration file."""

    try:
        filename = Path(file.filename or "").name
        if not filename:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNSUPPORTED_INPUT, "A configuration filename is required.")
        if Path(filename).suffix.lower() not in ALLOWED_CONFIGURATION_SUFFIXES:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNSUPPORTED_INPUT, "Unsupported file type. Use a .conf, .cfg, or .txt configuration file.")

        content = await file.read(MAX_CONFIGURATION_BYTES + 1)
        if not content:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.MALFORMED_CONFIGURATION, "The uploaded configuration file is empty.")
        if len(content) > MAX_CONFIGURATION_BYTES:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration file exceeds the 1 MB demo limit.")

        try:
            configuration_text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration file must be UTF-8 text.") from exc

        parser = None
        if CiscoParser.detect(configuration_text):
            parser = CiscoParser
        elif FortiGateParser.detect(configuration_text):
            parser = FortiGateParser
        elif PaloAltoParser.detect(configuration_text):
            parser = PaloAltoParser
        elif AstraNetParser.detect(configuration_text):
            parser = AstraNetParser
        if parser is None:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.UNSUPPORTED_INPUT, "Unsupported configuration input. The demo supports Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and fictional AstraNet synthetic configurations.")

        try:
            security_ir = parser.parse(configuration_text, source_file=filename)
        except (TypeError, ValueError) as exc:
            raise ApiError(status.HTTP_400_BAD_REQUEST, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration could not be parsed safely.") from exc

        controls = load_demo_controls()
        evaluations = DeterministicControlEngine().evaluate_all(security_ir, controls)
        evidence = [
            item
            for evaluation in evaluations
            for item in build_evidence(security_ir, evaluation)
        ]
        analysis_id = str(uuid4())
        response = AnalysisResponse(
            analysis_id=analysis_id,
            filename=filename,
            vendor=security_ir.device.vendor,
            device=AnalysisDeviceResponse(
                hostname=security_ir.device.hostname,
                version=security_ir.device.version,
                device_model=security_ir.device.device_model,
                serial_number=security_ir.device.serial_number,
                device_id=security_ir.device.device_id,
            ),
            results=[
                ControlResultSummary(
                    control_id=evaluation.control_id,
                    control_name=evaluation.control_name,
                    result=evaluation.result,
                    expected=evaluation.expected,
                    actual=evaluation.actual,
                    explanation=evaluation.explanation,
                )
                for evaluation in evaluations
            ],
            evidence=evidence,
            unknown_patterns=security_ir.unknown_patterns,
        )

        try:
            save_analysis_result(
                analysis_id=analysis_id,
                filename=filename,
                vendor=security_ir.device.vendor,
                response=response.model_dump(mode="json"),
                security_ir=security_ir.model_dump(mode="json"),
            )
        except Exception as exc:
            logger.exception("Could not persist analysis result %s", analysis_id)
            raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, ApiErrorCode.STORAGE_FAILURE, "The analysis could not be stored.") from exc

        return response
    except (ApiError,):
        raise
    except Exception as exc:
        logger.exception("Unexpected configuration analysis failure")
        raise ApiError(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            ApiErrorCode.INTERNAL_ERROR,
            "The configuration analysis failed due to an internal error.",
        ) from exc
    finally:
        await file.close()
