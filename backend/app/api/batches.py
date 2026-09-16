from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, UploadFile, Request

from ..config import BATCH_MAX_FILE_BYTES, BATCH_MAX_FILES, BATCH_MAX_TOTAL_BYTES
from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.batch import BatchAnalysis, BatchItem, BatchSummary
from ..domain.enums import ComplianceResult
from ..services.analysis_service import analyze_configuration_bytes
from ..storage.database import create_batch, get_batch, get_batch_items, update_batch, update_batch_item

router = APIRouter(prefix="/api/batches", tags=["batch analysis"])
ALLOWED_SUFFIXES = {".conf", ".cfg", ".txt"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _compliance_status(results: list) -> str:
    states = {item.result for item in results}
    if states == {ComplianceResult.PASS}:
        return "PASS"
    if states == {ComplianceResult.FAIL}:
        return "FAIL"
    if states == {ComplianceResult.UNKNOWN}:
        return "UNKNOWN"
    return "MIXED"


def _summary(items: list[BatchItem]) -> BatchSummary:
    return BatchSummary(
        total=len(items), processed=sum(item.processing_status in {"COMPLETED", "FAILED", "DUPLICATE"} for item in items),
        successful=sum(item.processing_status in {"COMPLETED", "DUPLICATE"} for item in items),
        failed=sum(item.processing_status == "FAILED" for item in items),
        duplicates=sum(item.processing_status == "DUPLICATE" for item in items),
        pass_analyses=sum(item.compliance_status == "PASS" for item in items),
        fail_analyses=sum(item.compliance_status == "FAIL" for item in items),
        unknown_analyses=sum(item.compliance_status == "UNKNOWN" for item in items),
    )


@router.post("/analyze", response_model=BatchAnalysis)
async def analyze_batch(request: Request, files: list[UploadFile] = File(...)) -> BatchAnalysis:
    if not files:
        raise ApiError(400, ApiErrorCode.BATCH_LIMIT_EXCEEDED, "At least one configuration file is required.")
    if len(files) > BATCH_MAX_FILES:
        raise ApiError(413, ApiErrorCode.BATCH_LIMIT_EXCEEDED, f"A batch may contain at most {BATCH_MAX_FILES} files.")
    submitted = _now()
    batch = BatchAnalysis(
        batch_id=str(uuid4()), submitted_at=submitted, total_items=len(files), processed_items=0,
        successful_items=0, failed_items=0, duplicate_items=0, status="PROCESSING",
        summary=BatchSummary(total=len(files), processed=0, successful=0, failed=0, duplicates=0, pass_analyses=0, fail_analyses=0, unknown_analyses=0),
    )
    items = [BatchItem(batch_item_id=str(uuid4()), source_filename=Path(file.filename or "").name, processing_status="QUEUED", created_at=submitted, updated_at=submitted) for file in files]
    create_batch(batch, items)
    total_bytes = 0
    for index, file in enumerate(files):
        item = items[index]
        item.processing_status = "PROCESSING"
        item.updated_at = _now()
        update_batch_item(item, batch.batch_id)
        try:
            suffix = Path(item.source_filename).suffix.lower()
            if suffix not in ALLOWED_SUFFIXES:
                raise ApiError(400, ApiErrorCode.UNSUPPORTED_INPUT, "Unsupported file type. Use a .conf, .cfg, or .txt configuration file.")
            content = await file.read(BATCH_MAX_FILE_BYTES + 1)
            total_bytes += len(content)
            if len(content) > BATCH_MAX_FILE_BYTES:
                raise ApiError(400, ApiErrorCode.MALFORMED_CONFIGURATION, "The configuration file exceeds the 1 MB limit.")
            if total_bytes > BATCH_MAX_TOTAL_BYTES:
                raise ApiError(413, ApiErrorCode.BATCH_LIMIT_EXCEEDED, "The batch exceeds the 10 MB total size limit.")
            actor = getattr(request.state, "actor", {})
            response = analyze_configuration_bytes(content, item.source_filename, actor_id=actor.get("user_id"))
            item.configuration_id = response.configuration.configuration_id if response.configuration else None
            item.device_id = response.device.device_id
            item.analysis_id = response.analysis_id
            item.content_sha256 = sha256(content).hexdigest()
            item.duplicate_of_configuration_id = response.configuration.duplicate_of_configuration_id if response.configuration else None
            item.compliance_status = _compliance_status(response.results)
            item.processing_status = "DUPLICATE" if item.duplicate_of_configuration_id else "COMPLETED"
        except ApiError as exc:
            item.processing_status = "FAILED"
            item.error_code, item.error_message = str(exc.code), exc.message
        except Exception:
            item.processing_status = "FAILED"
            item.error_code, item.error_message = ApiErrorCode.INTERNAL_ERROR.value, "The batch item could not be analyzed safely."
        finally:
            item.updated_at = _now()
            update_batch_item(item, batch.batch_id)
            await file.close()
    summary = _summary(items)
    batch.processed_items = summary.processed
    batch.successful_items = summary.successful
    batch.failed_items = summary.failed
    batch.duplicate_items = summary.duplicates
    batch.summary = summary
    batch.status = "COMPLETED_WITH_ERRORS" if summary.failed else "COMPLETED"
    update_batch(batch)
    return batch


@router.get("/{batch_id}", response_model=BatchAnalysis)
def read_batch(batch_id: str) -> BatchAnalysis:
    batch = get_batch(batch_id)
    if batch is None:
        raise ApiError(404, ApiErrorCode.VALIDATION_ERROR, "Batch was not found.")
    return batch


@router.get("/{batch_id}/items", response_model=list[BatchItem])
def read_batch_items(batch_id: str) -> list[BatchItem]:
    items = get_batch_items(batch_id)
    if items is None:
        raise ApiError(404, ApiErrorCode.VALIDATION_ERROR, "Batch was not found.")
    return items
