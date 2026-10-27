/// <reference types="vite/client" />

declare module "lucide-react" {
  export * from "lucide-react/dist/lucide-react";
}

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

