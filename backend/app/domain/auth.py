from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, Field, ConfigDict, StrictBool, field_validator
class Role(StrEnum): ADMIN="ADMIN"; AUDITOR="AUDITOR"; REVIEWER="REVIEWER"
class User(BaseModel): user_id:str; username:str; display_name:str; role:Role; active:bool; created_at:datetime; updated_at:datetime
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=256, repr=False)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.lower()


class UserCreateRequest(LoginRequest):
    password: str = Field(min_length=12, max_length=256, repr=False)
    display_name: str = Field(min_length=1, max_length=100)
    role: Role

    @field_validator("display_name")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Display name must not be blank")
        return value.strip()


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role | None = None
    active: StrictBool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256, repr=False)
