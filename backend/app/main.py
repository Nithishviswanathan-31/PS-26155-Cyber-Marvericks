from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.analyze import router as analyze_router
from .api.batches import router as batches_router
from .api.interpretations import router as interpretations_router
from .api.inventory import router as inventory_router
from .api.knowledge import router as knowledge_router
from .api.console import router as console_router
from .api.demo import router as demo_router
from .api.mappings import router as mappings_router
from .api.reanalyze import router as reanalyze_router
from .api.remediation import router as remediation_router
from .api.reports import router as reports_router
from .api.integrity import router as integrity_router
from .config import load_demo_controls, CatalogueError
from .domain.api_errors import ApiError, ApiErrorCode, error_payload
from .domain.schemas import HealthResponse
from .storage.database import initialize_database
from .storage.auth import initialize as initialize_auth
from .services.auth_service import AuthError, authorize_route, validate_settings
from .api.auth import router as auth_router, users_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_settings()
    initialize_database()
    initialize_auth()
    load_demo_controls()
    yield


app = FastAPI(
    title="PS 26155 Compliance Auditor — Emergency Demo MVP",
    version="0.1.0",
    lifespan=lifespan,
)

# Allow the local Vite frontend to communicate with the local FastAPI backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for audit_router in (analyze_router, batches_router, interpretations_router, inventory_router,
                     console_router, knowledge_router, demo_router, mappings_router,
                     reanalyze_router, remediation_router, reports_router):
    app.include_router(audit_router, dependencies=[Depends(authorize_route)])
app.include_router(integrity_router, dependencies=[Depends(authorize_route)])
app.include_router(auth_router)
app.include_router(users_router)


@app.exception_handler(AuthError)
async def auth_error_handler(_: Request, exc: AuthError):
    headers = {"Cache-Control": "no-store"}
    if exc.status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(status_code=exc.status, content=error_payload(exc.code, exc.message), headers=headers)


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(exc.code, exc.message, exc.detail),
    )


@app.exception_handler(CatalogueError)
async def catalogue_error_handler(_: Request, exc: CatalogueError) -> JSONResponse:
    return JSONResponse(status_code=500, content=error_payload(exc.error_code, exc.detail))


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    _: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_payload(
            ApiErrorCode.VALIDATION_ERROR,
            "Request validation failed.",
            jsonable_encoder([{key: value for key, value in error.items() if key not in {"input", "ctx"}} for error in exc.errors()]),
        ),
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")
