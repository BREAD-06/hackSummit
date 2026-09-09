// REST + WebSocket client for the detection server.
//
// Every path is relative. In production the server serves this bundle itself, so
// relative paths hit the right origin automatically; in dev, Vite proxies them.
// That is the whole reason there is no configurable base URL to get wrong when the
// dashboard is opened from another machine on the LAN.

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`/api${path}`, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch (cause) {
    // A network-level failure means the server is down or unreachable — worth a
    // distinct message, because it is the single most common deployment problem.
    throw new ApiError("cannot reach the detection server", 0, { cause: String(cause) });
  }

  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }

  if (!res.ok) {
    throw new ApiError(body?.detail || `${res.status} ${res.statusText}`, res.status, body);
  }
  return body;
}

export const api = {
  health: () => request("/health"),
  config: () => request("/config"),
  pqc: () => request("/pqc"),
  model: () => request("/model"),
  summary: () => request("/summary"),
  threats: ({ limit = 200, status } = {}) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (status) q.set("status", status);
    return request(`/threats?${q}`);
  },
  threat: (id) => request(`/threats/${id}`),
  timeline: () => request("/timeline"),
  users: () => request("/users"),
  scores: (limit = 500) => request(`/scores?limit=${limit}`),
  agents: () => request("/agents"),
  recentEvents: (limit = 60) => request(`/events/recent?limit=${limit}`),
  qtable: () => request("/rl/qtable"),
  rlStats: () => request("/rl/stats"),
  rlFeedback: (limit = 50) => request(`/rl/feedback?limit=${limit}`),
  resetPolicy: () => request("/rl/reset", { method: "POST" }),
  enrollToken: () => request("/enroll-token", { method: "POST" }),
  feedback: (threatId, action) =>
    request("/feedback", {
      method: "POST",
      body: JSON.stringify({ threat_id: threatId, action }),
    }),
};

export { ApiError };

/** Absolute ws:// or wss:// URL for the live feed, derived from the current origin. */
export function wsUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/ws`;
}

/**
 * Live threat feed with automatic reconnect.
 *
 * Returns a `close()` that stops reconnecting — without that flag a React strict-mode
 * remount would leave an orphan socket looping forever.
 */
export function connectLiveFeed({ onMessage, onStatus }) {
  let socket = null;
  let timer = null;
  let closed = false;
  let attempt = 0;

  const open = () => {
    if (closed) return;
    onStatus?.(attempt === 0 ? "connecting" : "reconnecting");
    socket = new WebSocket(wsUrl());

    socket.onopen = () => {
      attempt = 0;
      onStatus?.("live");
    };
    socket.onmessage = (evt) => {
      try {
        onMessage?.(JSON.parse(evt.data));
      } catch {
        /* a frame we cannot parse is not worth tearing the socket down for */
      }
    };
    socket.onclose = () => {
      if (closed) return;
      onStatus?.("offline");
      // Back off to 10s so a dashboard left open against a stopped server does not
      // hammer the network, but still recovers on its own when the server returns.
      const delay = Math.min(10000, 500 * 2 ** attempt++);
      timer = setTimeout(open, delay);
    };
    socket.onerror = () => socket?.close();
  };

  open();

  return () => {
    closed = true;
    clearTimeout(timer);
    socket?.close();
  };
}
