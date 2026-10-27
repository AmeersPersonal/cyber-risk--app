import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  envPrefix: ["VITE_", "API_"],
  server: {
    proxy: {
      // Intercepts any frontend fetch starting with '/scan'
      "/scan": {
        target: "http://localhost:8000", // Path to your backend server
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
