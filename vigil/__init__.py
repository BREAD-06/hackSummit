"""VIGIL AI — shared core package.

Imported by BOTH the endpoint agent and the detection server, so it must stay
free of heavy dependencies (no scikit-learn / fastapi here). It contains:

- ``vigil.pqc``     : post-quantum secure channel (ML-KEM-512 + ML-DSA-44 + AES-256-GCM)
- ``vigil.schema``  : the canonical event / batch data models
- ``vigil.features``: rolling per-(user, host, hour) feature engineering
"""

__version__ = "3.0.0"
