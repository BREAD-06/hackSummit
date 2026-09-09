"""VIGIL AI Endpoint Agent.

The lightweight half of the system: runs unprivileged on a monitored workstation,
observes file / removable-media / session activity (metadata only), and streams it
to the detection server over a post-quantum-secured channel.

    python -m agent.keygen     # once, per endpoint
    python -m agent.main       # stream

Kept import-light on purpose — ``agent.config`` and ``agent.keygen`` are usable
without ``watchdog``, ``psutil`` or ``httpx`` installed, so provisioning works even
on a box that will never run collectors.
"""

__all__ = ["config", "keygen", "buffer", "transport", "collectors", "main"]
