"""Prepare observed inventory records; persistence commits them with the audit."""
from datetime import datetime, timezone
from uuid import uuid4, uuid5, NAMESPACE_URL

from ..domain.inventory import Device, Configuration
from ..domain.security_ir import SecurityIR


def prepare_inventory(security_ir: SecurityIR, filename: str, fingerprint: str, existing_device: Device | None = None) -> tuple[Device, Configuration]:
    now = datetime.now(timezone.utc)
    observed = security_ir.device
    if existing_device and existing_device.vendor != observed.vendor:
        raise ValueError("Selected device vendor does not match the parsed configuration.")
    identity_parts = (observed.vendor, observed.hostname, observed.platform, observed.version, observed.device_model, observed.serial_number)
    stable_key = "|".join(item or "" for item in identity_parts)
    stable_device_id = str(uuid5(NAMESPACE_URL, f"ps26155:device:{stable_key}")) if observed.hostname else str(uuid4())
    device = Device(
        device_id=existing_device.device_id if existing_device else stable_device_id, hostname=observed.hostname, vendor=observed.vendor,
        platform=observed.platform, software_version=observed.version, device_model=observed.device_model,
        serial_number=observed.serial_number,
        metadata={"identity_basis": "CONFIGURATION_OBSERVATION", "source_filename": filename},
        metadata_provenance=observed.metadata_provenance,
        created_at=existing_device.created_at if existing_device else now, updated_at=now,
    )
    configuration = Configuration(
        configuration_id=str(uuid4()), device_id=device.device_id,
        source_filename=filename, content_sha256=fingerprint,
        detected_vendor=observed.vendor, uploaded_at=now,
        parser_status="PARTIAL" if security_ir.unknown_patterns or any(v is None for v in security_ir.normalized_properties.values()) else "PARSED",
        created_at=now, updated_at=now,
    )
    return device, configuration
