import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In production the detection server serves `dist/` itself (see server/main.py), so
// the app always calls the API with relative paths. In dev, Vite serves the app on
// :5173 and proxies those same relative paths to the real server — including the
// WebSocket, which is why `ws: true` matters. Point VIGIL_SERVER at another host to
// develop the dashboard against a server running elsewhere.
const target = process.env.VIGIL_SERVER || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target, ws: true, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    // The server mounts dist/assets at /assets and serves index.html at /, so the
    // default layout is exactly what it expects. Keep it.
    assetsDir: "assets",
    sourcemap: false,
  },
});
