from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.analyze import router as analyze_router
from .api.demo import router as demo_router
from .api.mappings import router as mappings_router
from .api.reanalyze import router as reanalyze_router
from .api.remediation import router as remediation_router
from .api.reports import router as reports_router
from .config import load_demo_controls
from .domain.api_errors import ApiError, ApiErrorCode, error_payload
from .domain.schemas import HealthResponse
from .storage.database import initialize_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
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

app.include_router(analyze_router)
app.include_router(demo_router)
app.include_router(mappings_router)
app.include_router(reanalyze_router)
app.include_router(remediation_router)
app.include_router(reports_router)


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(exc.code, exc.message, exc.detail),
    )


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
            jsonable_encoder(exc.errors()),
        ),
    )


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")