/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the internal/api backend, e.g. "https://api.zerodock.example". Empty = same-origin. */
  readonly VITE_API_BASE_URL?: string;
  /** Freshness window in milliseconds — see verify/freshness.ts. Defaults if unset. */
  readonly VITE_FRESHNESS_WINDOW_MS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
