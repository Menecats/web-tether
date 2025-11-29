import { SocksTunnelError } from "./proxy/socks.common.ts";
import { createSocksServer } from "./proxy/socks.server.ts";

const controller = new AbortController();

Deno.addSignalListener("SIGINT", () => {
  console.log("interrupt");
  controller.abort();
});

await createSocksServer({
  listen: { port: 1080 },
  signal: controller.signal,

  socks4: { enabled: true, auth: { enabled: false } },
  socks5: { enabled: true, auth: { enabled: false } },

  log: (level, ...content) => console.log(level, ...content),
  tunnel: async (destination) => {
    console.log("connecting to ", destination);

    try {
      return {
        ok: true,
        tunnel: await Deno.connect({
          hostname: destination.host,
          port: destination.port,
        }),
      };
    } catch (err) {
      let error: SocksTunnelError;
      if (err instanceof Deno.errors.ConnectionRefused) {
        error = "connection-refused";
      } else if (err instanceof Deno.errors.NetworkUnreachable) {
        error = "network-unreachable";
      } else {
        error = "general-failure";
      }
      return { ok: false, error };
    }
  },
});
