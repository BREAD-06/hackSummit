"""ML subpackage — Isolation Forest anomaly detection over live feature windows."""

from server.ml.model import DetectionModel, DEFAULT_MODEL_PATH

__all__ = ["DetectionModel", "DEFAULT_MODEL_PATH"]
