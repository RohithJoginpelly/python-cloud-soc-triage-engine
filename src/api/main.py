"""ASGI entry point for the AI SOC Copilot API."""

from src.api.app import create_app


app = create_app()
