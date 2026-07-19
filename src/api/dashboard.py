"""Server-rendered SOC analyst dashboard."""

from __future__ import annotations

from collections import Counter
from hmac import compare_digest
from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Form,
    Request,
    status,
)
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates


router = APIRouter(
    include_in_schema=False
)

TEMPLATE_DIRECTORY = (
    Path(__file__).resolve().parent
    / "templates"
)

templates = Jinja2Templates(
    directory=str(TEMPLATE_DIRECTORY)
)

OPEN_CASE_STATUSES = {
    "new",
    "triage",
    "investigating",
    "contained",
}


def _authenticated(
    request: Request,
) -> bool:
    """Return whether the browser session is authenticated."""

    return bool(
        request.session.get("authenticated")
    )


def _login_redirect() -> RedirectResponse:
    """Redirect an unauthenticated user to login."""

    return RedirectResponse(
        url="/dashboard/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/")
def root() -> RedirectResponse:
    """Redirect the root URL to the dashboard."""

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/dashboard/login",
    response_class=HTMLResponse,
)
def dashboard_login_page(
    request: Request,
) -> Response:
    """Display the dashboard authentication form."""

    if _authenticated(request):
        return RedirectResponse(
            url="/dashboard",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return templates.TemplateResponse(
        request=request,
        name="dashboard/login.html",
        context={
            "error": None,
        },
    )


@router.post(
    "/dashboard/login",
    response_class=HTMLResponse,
)
def dashboard_login(
    request: Request,
    api_key: Annotated[
        str,
        Form(min_length=1),
    ],
) -> Response:
    """Exchange the SOC API key for a browser session."""

    configured_key = getattr(
        request.app.state,
        "api_key",
        None,
    )

    supplied_key = api_key.strip()

    valid = (
        isinstance(configured_key, str)
        and bool(configured_key)
        and bool(supplied_key)
        and compare_digest(
            supplied_key.encode("utf-8"),
            configured_key.encode("utf-8"),
        )
    )

    if not valid:
        return templates.TemplateResponse(
            request=request,
            name="dashboard/login.html",
            context={
                "error": "Invalid SOC API key.",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    request.session.clear()
    request.session["authenticated"] = True

    return RedirectResponse(
        url="/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/dashboard/logout")
def dashboard_logout(
    request: Request,
) -> RedirectResponse:
    """Clear the authenticated browser session."""

    request.session.clear()

    return RedirectResponse(
        url="/dashboard/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard_home(
    request: Request,
    case_status: str | None = None,
) -> Response:
    """Display case metrics and the analyst case queue."""

    if not _authenticated(request):
        return _login_redirect()

    store = request.app.state.case_store

    normalized_status = (
        case_status.strip().lower()
        if isinstance(case_status, str)
        and case_status.strip()
        else None
    )

    allowed_statuses = {
        "new",
        "triage",
        "investigating",
        "contained",
        "resolved",
        "closed",
        "false_positive",
    }

    if normalized_status not in allowed_statuses:
        normalized_status = None

    cases = store.list_cases(
        status=normalized_status,
        limit=500,
    )

    all_cases = store.list_cases(
        limit=500
    )

    status_counts = Counter(
        case.status
        for case in all_cases
    )

    metrics = {
        "total": len(all_cases),
        "open": sum(
            1
            for case in all_cases
            if case.status in OPEN_CASE_STATUSES
        ),
        "p1": sum(
            1
            for case in all_cases
            if case.priority == "P1"
            and case.status in OPEN_CASE_STATUSES
        ),
        "unassigned": sum(
            1
            for case in all_cases
            if case.assigned_to is None
            and case.status in OPEN_CASE_STATUSES
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "cases": cases,
            "metrics": metrics,
            "status_counts": status_counts,
            "selected_status": normalized_status,
        },
    )


@router.get(
    "/dashboard/cases/{case_id}",
    response_class=HTMLResponse,
)
def dashboard_case_detail(
    request: Request,
    case_id: str,
) -> Response:
    """Display complete details for one SOC case."""

    if not _authenticated(request):
        return _login_redirect()

    store = request.app.state.case_store

    case = store.get_case(case_id)

    if case is None:
        return templates.TemplateResponse(
            request=request,
            name="dashboard/not_found.html",
            context={
                "case_id": case_id,
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )

    audit_events = store.get_audit_events(
        case.case_id
    )

    packet = case.packet

    mitre_techniques = packet.get(
        "mitre_techniques",
        [],
    )

    copilot_draft = None

    if isinstance(case.copilot_result, dict):
        draft = case.copilot_result.get(
            "draft"
        )

        if isinstance(draft, dict):
            copilot_draft = draft

    return templates.TemplateResponse(
        request=request,
        name="dashboard/case_detail.html",
        context={
            "case": case,
            "packet": packet,
            "mitre_techniques": mitre_techniques,
            "copilot_draft": copilot_draft,
            "audit_events": audit_events,
        },
    )
