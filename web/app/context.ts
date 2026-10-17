import { createContext } from "react-router";

export interface CloudflareContext {
  env: Env;
  ctx: ExecutionContext;
}

/** Worker bindings and execution context, set once per request in workers/app.ts. */
export const cloudflareContext = createContext<CloudflareContext>();
