"""Identity models for SOC analyst accounts."""

from __future__ import annotations

from dataclasses import dataclass


ALLOWED_ANALYST_ROLES = {
    "analyst",
    "senior_analyst",
    "admin",
}


@dataclass(frozen=True, slots=True)
class AnalystAccount:
    """Authenticated user allowed to access the SOC."""

    user_id: str
    email: str
    display_name: str
    role: str
    is_active: bool
    created_at: str
    updated_at: str
    last_login_at: str | None = None

    def __post_init__(self) -> None:
        normalized_email = (
            self.email.strip().lower()
        )

        normalized_role = (
            self.role.strip().lower()
        )

        if normalized_role not in (
            ALLOWED_ANALYST_ROLES
        ):
            raise ValueError(
                f"Unsupported analyst role: "
                f"{self.role}"
            )

        object.__setattr__(
            self,
            "email",
            normalized_email,
        )

        object.__setattr__(
            self,
            "role",
            normalized_role,
        )


@dataclass(frozen=True, slots=True)
class IdentityAuditEvent:
    """Append-only identity security audit event."""

    event_id: str
    actor_user_id: str | None
    actor_email: str
    target_user_id: str | None
    action: str
    details: dict[str, object]
    created_at: str
