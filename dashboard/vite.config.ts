import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built bundle is served by the collector itself, so everything is
// self-contained: no CDN fonts, no external map tiles, no analytics. An
// operator console that needs the public internet to render is a console that
// stops working exactly when you need it.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      // During development the API runs separately; in deployment both are
      // served from the same origin and this proxy is unused.
      "/api": {
        target: "http://127.0.0.1:8088",
        changeOrigin: true,
      },
    },
  },
});
