import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  envPrefix: ["VITE_", "API_"],
  server: {
    proxy: {
      "/scan": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      "/verify": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      "/health": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      "/tools": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      "/cves": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
      "/report": {
        target: "http://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
