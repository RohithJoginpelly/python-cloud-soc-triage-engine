"""Role-based access-control permissions for SOC analysts."""

from __future__ import annotations

from enum import StrEnum

from src.identity.models import (
    ALLOWED_ANALYST_ROLES,
)


class Permission(StrEnum):
    """Actions that may be performed in the SOC platform."""

    VIEW_CASES = "view_cases"
    VIEW_AUDIT_LOG = "view_audit_log"
    ADD_NOTES = "add_notes"
    UPDATE_CASE_STATUS = "update_case_status"
    ASSIGN_SELF = "assign_self"
    REASSIGN_CASES = "reassign_cases"
    RESOLVE_CASES = "resolve_cases"
    MANAGE_ANALYSTS = "manage_analysts"


ROLE_PERMISSIONS: dict[
    str,
    frozenset[Permission],
] = {
    "analyst": frozenset(
        {
            Permission.VIEW_CASES,
            Permission.VIEW_AUDIT_LOG,
            Permission.ADD_NOTES,
            Permission.UPDATE_CASE_STATUS,
            Permission.ASSIGN_SELF,
        }
    ),
    "senior_analyst": frozenset(
        {
            Permission.VIEW_CASES,
            Permission.VIEW_AUDIT_LOG,
            Permission.ADD_NOTES,
            Permission.UPDATE_CASE_STATUS,
            Permission.ASSIGN_SELF,
            Permission.REASSIGN_CASES,
            Permission.RESOLVE_CASES,
        }
    ),
    "admin": frozenset(Permission),
}


def normalize_role(role: str) -> str:
    """Normalize and validate an analyst role."""

    if not isinstance(role, str):
        raise TypeError(
            "Role must be a string."
        )

    normalized_role = role.strip().lower()

    if normalized_role not in ALLOWED_ANALYST_ROLES:
        raise ValueError(
            f"Unsupported analyst role: {role}"
        )

    return normalized_role


def permissions_for_role(
    role: str,
) -> frozenset[Permission]:
    """Return the permissions assigned to a role."""

    normalized_role = normalize_role(role)

    return ROLE_PERMISSIONS[
        normalized_role
    ]


def has_permission(
    role: str,
    permission: Permission | str,
) -> bool:
    """Return whether a role has a permission."""

    normalized_role = normalize_role(role)

    try:
        normalized_permission = Permission(
            permission
        )
    except ValueError:
        return False

    return (
        normalized_permission
        in ROLE_PERMISSIONS[normalized_role]
    )


def require_permission(
    role: str,
    permission: Permission | str,
) -> None:
    """Raise PermissionError when access is denied."""

    try:
        normalized_permission = Permission(
            permission
        )
    except ValueError as error:
        raise PermissionError(
            f"Unknown permission: {permission}"
        ) from error

    if not has_permission(
        role,
        normalized_permission,
    ):
        raise PermissionError(
            f"Role '{normalize_role(role)}' "
            f"does not have permission "
            f"'{normalized_permission.value}'."
        )
