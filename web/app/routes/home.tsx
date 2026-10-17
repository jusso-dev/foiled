import { cloudflareContext } from "../context";
import { getHealth } from "../lib/api.server";
import type { Route } from "./+types/home";

export function meta(_: Route.MetaArgs) {
  return [{ title: "Foiled console" }];
}

export async function loader({ context }: Route.LoaderArgs) {
  const { env } = context.get(cloudflareContext);
  return { health: await getHealth(env.API) };
}

export default function Home({ loaderData }: Route.ComponentProps) {
  const { health } = loaderData;
  return (
    <main>
      <h1>Foiled</h1>
      <p>
        API: {health ? `${health.status} (${health.service} ${health.version})` : "unreachable"}
      </p>
    </main>
  );
}
