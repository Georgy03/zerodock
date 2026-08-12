/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Keep browser API requests same-origin during local development. The
  // frontend calls /v1/... by default; Vite forwards only that path prefix to
  // the Go API on port 8080, avoiding a development-only CORS dependency.
  server: {
    proxy: {
      "/v1": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  test: {
    // "node" (not "jsdom") for the verify/* tests: they exercise real
    // WebCrypto (crypto.subtle) and pkijs chain validation, and Node's
    // native globalThis.crypto is a closer match to a real browser's
    // than jsdom's polyfilled one. Component tests, if any are added
    // later, can override this per-file via a `// @vitest-environment
    // jsdom` comment.
    environment: "node",
    globals: true,
  },
});
