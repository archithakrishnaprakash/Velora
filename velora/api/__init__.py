"""Web API and dashboard (Starlette + Jinja2).

Built on Starlette, which is FastAPI's foundation. The route layer is intentionally thin
and could be moved to FastAPI without changing the service layer. Secure defaults: binds to
loopback by default, sets security headers, and never exposes secrets.
"""
from .app import create_asgi_app

__all__ = ["create_asgi_app"]
