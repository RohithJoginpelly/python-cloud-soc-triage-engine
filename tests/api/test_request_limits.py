"""Request body size middleware tests."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.request_limits import (
    RequestBodyLimitMiddleware,
)


def build_app(
    *,
    max_body_bytes: int = 16,
) -> FastAPI:
    """Create a small isolated test application."""

    app = FastAPI()

    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )

    @app.post("/echo")
    async def echo(
        request: Request,
    ):
        body = await request.body()

        return {
            "size": len(body),
            "body": body.decode("utf-8"),
        }

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


def test_small_request_body_is_allowed():
    app = build_app(
        max_body_bytes=16
    )

    client = TestClient(app)

    response = client.post(
        "/echo",
        content=b"small-body",
    )

    assert response.status_code == 200

    assert response.json() == {
        "size": 10,
        "body": "small-body",
    }


def test_body_equal_to_limit_is_allowed():
    app = build_app(
        max_body_bytes=8
    )

    client = TestClient(app)

    response = client.post(
        "/echo",
        content=b"12345678",
    )

    assert response.status_code == 200
    assert response.json()["size"] == 8


def test_declared_oversized_body_is_rejected():
    app = build_app(
        max_body_bytes=8
    )

    client = TestClient(app)

    response = client.post(
        "/echo",
        content=b"123456789",
    )

    assert response.status_code == 413

    assert response.json()["detail"] == (
        "Request body exceeds the "
        "configured size limit."
    )

    assert response.headers[
        "x-max-request-body-bytes"
    ] == "8"


def test_streamed_oversized_body_is_rejected():
    app = build_app(
        max_body_bytes=8
    )

    client = TestClient(app)

    def body_chunks():
        yield b"1234"
        yield b"5678"
        yield b"9"

    response = client.post(
        "/echo",
        content=body_chunks(),
    )

    assert response.status_code == 413

    assert response.headers[
        "x-max-request-body-bytes"
    ] == "8"


def test_get_requests_are_not_body_limited():
    app = build_app(
        max_body_bytes=1
    )

    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok"
    }


def test_invalid_limit_is_rejected():
    app = FastAPI()

    try:
        app.add_middleware(
            RequestBodyLimitMiddleware,
            max_body_bytes=0,
        )

        client = TestClient(app)

        client.get("/")
    except ValueError as error:
        assert (
            "must be at least one"
            in str(error)
        )
    else:
        raise AssertionError(
            "Expected invalid body limit "
            "to raise ValueError."
        )
