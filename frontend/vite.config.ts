import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const api = process.env.VIGIL_API_URL ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1000 },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: api, changeOrigin: true, ws: true },
    },
  },
});
