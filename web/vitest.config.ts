import { defineConfig } from "vitest/config";

// Unit tests run in Node without the React Router or Cloudflare Vite plugins.
export default defineConfig({
  test: {
    include: ["app/**/*.test.{ts,tsx}"],
  },
});
