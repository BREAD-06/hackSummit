"""HTTP/WebSocket surface: the agent ingest path and the SOC dashboard API."""

from server.api.agent_routes import router as agent_router
from server.api.soc_routes import router as soc_router
from server.api.ws import ConnectionManager

__all__ = ["agent_router", "soc_router", "ConnectionManager"]
