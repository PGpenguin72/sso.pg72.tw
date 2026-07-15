import { cloudflare } from "@cloudflare/vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const DEV_CSP_NONCE = "cGc3Mi12aXRlLWRldg==";

export default defineConfig(({ command }) => ({
  html:
    command === "serve"
      ? {
          cspNonce: DEV_CSP_NONCE,
        }
      : undefined,
  plugins: [react(), cloudflare()],
}));
