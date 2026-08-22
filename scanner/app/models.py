"""Validated request models for the internal scanner API."""

from typing import Literal

from pydantic import BaseModel, Field, SecretStr


class QuickScanRequest(BaseModel):
    """Public tokenless quick-scan request."""

    target: str = Field(min_length=8, max_length=2048)


class IdentityProfile(BaseModel):
    """Ephemeral identity metadata and secret request headers."""

    label: str = Field(min_length=1, max_length=64)
    role: str = Field(default="", max_length=64)
    tenant: str = Field(default="", max_length=64)
    headers: dict[str, SecretStr] = Field(min_length=1, max_length=5)


class WorkflowIdentityProfile(IdentityProfile):
    """Workflow identity that may acquire its only credential from an adapter."""

    headers: dict[str, SecretStr] = Field(default_factory=dict, max_length=5)


class AuthorizationPolicyRule(BaseModel):
    """One explicit expected access decision."""

    method: Literal["GET"] = "GET"
    path: str = Field(min_length=1, max_length=512)
    identity: str = Field(min_length=1, max_length=64)
    expected: Literal["allow", "deny"]


class DeepScanRequest(BaseModel):
    """Authorized cross-user scan request with ephemeral credentials."""

    target: str = Field(min_length=8, max_length=2048)
    object_paths: list[str] = Field(min_length=1, max_length=5)
    admin_paths: list[str] = Field(min_length=1, max_length=5)
    enumeration_existing_paths: list[str] = Field(default_factory=list, max_length=5)
    enumeration_missing_paths: list[str] = Field(default_factory=list, max_length=5)
    identities: list[IdentityProfile] = Field(min_length=2, max_length=2)
    policy_rules: list[AuthorizationPolicyRule] = Field(min_length=1, max_length=30)


class SourceScanRequest(BaseModel):
    """Static scan request confined to the mounted upload root."""

    repository_path: str = Field(min_length=1, max_length=512)


class DiscoveryRequest(BaseModel):
    """Endpoint-discovery request confined to the mounted upload root."""

    repository_path: str = Field(min_length=1, max_length=512)
    target: str = Field(min_length=8, max_length=2048)


class AssetVerificationRequest(BaseModel):
    """Exact-origin ownership challenge request."""

    origin: str = Field(min_length=8, max_length=2048)
    challenge: str = Field(min_length=24, max_length=128)
    verification_method: Literal["file", "header", "dns"] = "file"


class MutationTargetAuthorizationRequest(BaseModel):
    """Defense-in-depth proof required for local or verified-remote mutation targets."""

    mode: Literal["local", "verified-remote"] = "local"
    challenge: str | None = Field(default=None, min_length=24, max_length=128)
    verification_method: Literal["file", "header", "dns"] | None = None


class MutationScanRequest(BaseModel):
    """Explicit guarded create-and-cleanup mutation request."""

    target: str = Field(min_length=8, max_length=2048)
    path: str = Field(min_length=14, max_length=512)
    body: dict[str, object]
    identity: IdentityProfile
    target_authorization: MutationTargetAuthorizationRequest = Field(
        default_factory=MutationTargetAuthorizationRequest,
    )


class AuthenticationAdapterRequest(BaseModel):
    """Optional ephemeral authentication flow for a local workflow identity."""

    type: Literal["none", "json-login"] = "none"
    path: str | None = Field(default=None, max_length=512)
    username_field: str = Field(default="username", min_length=1, max_length=64)
    password_field: str = Field(default="password", min_length=1, max_length=64)
    username: SecretStr | None = None
    password: SecretStr | None = None
    token_json_path: str = Field(default="accessToken", min_length=1, max_length=128)
    header_name: str = Field(default="authorization", min_length=1, max_length=64)
    scheme: str = Field(default="Bearer", max_length=32)


class WorkflowStepRequest(BaseModel):
    """One bounded request in a disposable local workflow."""

    name: str = Field(min_length=1, max_length=64)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(min_length=14, max_length=512)
    body: dict[str, object] | None = None
    expected: Literal["allow", "deny"]


class WorkflowScanRequest(BaseModel):
    """A guarded local or verified-remote workflow with mandatory cleanup."""

    target: str = Field(min_length=8, max_length=2048)
    identity: WorkflowIdentityProfile
    authentication: AuthenticationAdapterRequest = Field(default_factory=AuthenticationAdapterRequest)
    steps: list[WorkflowStepRequest] = Field(min_length=1, max_length=8)
    target_authorization: MutationTargetAuthorizationRequest = Field(
        default_factory=MutationTargetAuthorizationRequest,
    )
