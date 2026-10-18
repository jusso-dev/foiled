import { defineConfig } from "vitest/config";

// Unit tests run in Node without the React Router or Cloudflare Vite plugins.
export default defineConfig({
  test: {
    include: ["app/**/*.test.{ts,tsx}"],
    // Let design-system tests read stylesheets with `?raw` (Vitest blanks CSS by default).
    css: { include: [/\.css(\?raw)?$/] },
  },
});
