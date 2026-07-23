"""Dependency providers for the SOC API."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import Depends, Request

from src.cases.store import SQLiteCaseStore


def get_case_store(
    request: Request,
) -> SQLiteCaseStore:
    """Return the case store configured for the app."""

    return request.app.state.case_store


def get_input_root(
    request: Request,
) -> Path:
    """Return the allowed security-event input directory."""

    return request.app.state.input_root


def get_database_path(
    request: Request,
) -> Path:
    """Return the configured SQLite database path."""

    return request.app.state.database_path


CaseStoreDependency = Annotated[
    SQLiteCaseStore,
    Depends(get_case_store),
]

InputRootDependency = Annotated[
    Path,
    Depends(get_input_root),
]

DatabasePathDependency = Annotated[
    Path,
    Depends(get_database_path),
]
