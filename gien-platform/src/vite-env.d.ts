/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly DEV: boolean;
  readonly VITE_GIEN_EVIDENCE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
