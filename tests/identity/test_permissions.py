import pytest

from src.identity.permissions import (
    Permission,
    has_permission,
    permissions_for_role,
    require_permission,
)


def test_analyst_can_view_and_update_cases():
    assert has_permission(
        "analyst",
        Permission.VIEW_CASES,
    )

    assert has_permission(
        "analyst",
        Permission.ADD_NOTES,
    )

    assert has_permission(
        "analyst",
        Permission.UPDATE_CASE_STATUS,
    )

    assert has_permission(
        "analyst",
        Permission.ASSIGN_SELF,
    )


def test_analyst_cannot_reassign_cases():
    assert not has_permission(
        "analyst",
        Permission.REASSIGN_CASES,
    )


def test_analyst_cannot_resolve_cases():
    assert not has_permission(
        "analyst",
        Permission.RESOLVE_CASES,
    )


def test_analyst_cannot_manage_accounts():
    assert not has_permission(
        "analyst",
        Permission.MANAGE_ANALYSTS,
    )


def test_senior_analyst_can_reassign_and_resolve():
    assert has_permission(
        "senior_analyst",
        Permission.REASSIGN_CASES,
    )

    assert has_permission(
        "senior_analyst",
        Permission.RESOLVE_CASES,
    )

    assert not has_permission(
        "senior_analyst",
        Permission.MANAGE_ANALYSTS,
    )


def test_admin_has_every_permission():
    admin_permissions = permissions_for_role(
        "admin"
    )

    assert admin_permissions == frozenset(
        Permission
    )


def test_role_normalization():
    assert has_permission(
        " Senior_Analyst ",
        Permission.RESOLVE_CASES,
    )


def test_unknown_role_is_rejected():
    with pytest.raises(
        ValueError,
        match="Unsupported analyst role",
    ):
        permissions_for_role(
            "superuser"
        )


def test_unknown_permission_is_denied():
    assert not has_permission(
        "admin",
        "delete_everything",
    )


def test_require_permission_allows_access():
    require_permission(
        "senior_analyst",
        Permission.RESOLVE_CASES,
    )


def test_require_permission_rejects_access():
    with pytest.raises(
        PermissionError,
        match="does not have permission",
    ):
        require_permission(
            "analyst",
            Permission.MANAGE_ANALYSTS,
        )
