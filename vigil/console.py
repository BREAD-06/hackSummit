"""Console encoding and buffering, made safe before anything is printed.

Two things about a Windows console stop being true the moment output is piped to a
log file, a service wrapper, or Task Scheduler — which is exactly how a monitoring
agent runs in production:

**Encoding.** Python gives a real console UTF-8, but gives a *pipe* whatever the
legacy locale is — usually cp1252. So the agent prints fine interactively and then
dies with ``UnicodeEncodeError`` when redirected. The failing character does not
have to be decorative: a watched file named ``résumé.docx`` is enough, and file
paths are the one thing this system logs constantly.

**Buffering.** A console is line-buffered; a pipe is block-buffered at 8 KB. A
long-running agent's progress lines then sit in the buffer for minutes, so
``tail -f`` on the log shows nothing and the process looks hung. Worse, a crash
loses whatever was still buffered — the diagnostic lines leading up to the failure
are the ones you needed.

Call :func:`enable_utf8` at the top of every entry point, before configuring
logging — ``logging.basicConfig`` captures ``sys.stderr`` as it is at that moment.
"""

from __future__ import annotations

import sys


def enable_utf8() -> None:
    """Make stdout/stderr accept any text, and flush it promptly.

    ``errors="replace"`` is the belt to the UTF-8 braces: even on a stream that
    refuses to be reconfigured, a stray character degrades to ``?`` instead of
    taking down a monitoring agent that was supposed to be running unattended.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except (ValueError, OSError):
            # A stream someone else already wrapped (pytest's capture, a service
            # harness). Nothing to do, and nothing worth failing startup over.
            pass
