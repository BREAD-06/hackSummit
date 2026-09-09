"""Storage subpackage — swappable persistence layer (SQLite ships by default)."""

from server.db.base import Storage
from server.db.sqlite_store import SQLiteStorage

__all__ = ["Storage", "SQLiteStorage"]
