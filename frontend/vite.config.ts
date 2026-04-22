import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// Build the React app directly into the Python package's static dir so that
// `pip install` + `pcap-viz` works end-to-end without a separate asset copy.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, "../src/pcap_viz/static"),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8765",
    },
  },
});
