from fastapi import APIRouter

from ..domain.api_errors import ApiError, ApiErrorCode
from ..domain.inventory import Device, ConfigurationHistory, DeviceAnalysisHistory
from ..domain.properties import PROPERTY_DEFINITIONS, parser_capability
from ..storage.database import get_device, get_configuration_history, get_device_analysis_history

router = APIRouter(prefix="/api", tags=["device and configuration context"])


@router.get("/devices/{device_id}", response_model=Device)
def device_detail(device_id: str):
    result = get_device(device_id)
    if result is None:
        raise ApiError(404, ApiErrorCode.DEVICE_NOT_FOUND, "Device was not found.")
    return result


@router.get("/devices/{device_id}/analyses", response_model=DeviceAnalysisHistory)
def device_analysis_history(device_id: str):
    result = get_device_analysis_history(device_id)
    if result is None:
        raise ApiError(404, ApiErrorCode.DEVICE_NOT_FOUND, "Device was not found.")
    return result


@router.get("/configurations/{configuration_id}", response_model=ConfigurationHistory)
def configuration_detail(configuration_id: str):
    result = get_configuration_history(configuration_id)
    if result is None:
        raise ApiError(404, ApiErrorCode.CONFIGURATION_NOT_FOUND, "Configuration was not found.")
    return result


@router.get("/parser-capabilities")
def capabilities():
    vendors = ("cisco_iosxe", "fortigate_fortios", "paloalto_panos", "astranet")
    return {path: {
        "type": definition.value_type.__name__, "description": definition.description,
        "provenance_expectations": definition.provenance_expectation,
        "vendors": {vendor: parser_capability(path, vendor) for vendor in vendors},
    } for path, definition in PROPERTY_DEFINITIONS.items()}
