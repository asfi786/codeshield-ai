"""Pydantic v2 request/response models for the CodeShield AI API."""

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Request body for starting a repository analysis job."""

    repo_url: str = Field(..., min_length=3, max_length=500)
    github_token: str | None = Field(default=None, max_length=200)
    deep_scan: bool = False


class JobAcceptedResponse(BaseModel):
    """Immediate response when an analysis job is accepted (HTTP 202)."""

    job_id: str
    status: str


class RegisterRequest(BaseModel):
    """Create a new user account."""

    name: str = Field(..., min_length=1, max_length=80)
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    """Sign in with email and password."""

    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)


class UserResponse(BaseModel):
    """Public user profile returned after register/login/me."""

    name: str
    email: str
    picture: str | None = None


class JobStatusResponse(BaseModel):
    """Pollable status of an analysis job, including the final result."""

    job_id: str
    status: str
    progress: int = Field(ge=0, le=100)
    stage: str
    result: dict | None = None
    error: str | None = None


class ValidateResponse(BaseModel):
    """Result of validating a GitHub repository URL."""

    valid: bool
    owner: str | None = None
    repo: str | None = None
    private: bool = False


class HealthResponse(BaseModel):
    """Service health payload."""

    status: str
    version: str
    timestamp: str
