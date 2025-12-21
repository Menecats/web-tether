import { ConnectionTunnelErrorReason } from "./common/communication.ts";
import { createLogger } from "./common/log.ts";
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

  log: createLogger((level, content) => console.log(level, ...content)),
  tunnel: async (destination, log) => {
    try {
      const tunnel = await Deno.connect({
        hostname: destination.host,
        port: destination.port,
      });

      log.trace(
        `Connected to ${tunnel.remoteAddr.hostname}:${tunnel.remoteAddr.port} from ${tunnel.localAddr.hostname}:${tunnel.localAddr.port}.`,
      );

      return { ok: true, tunnel };
    } catch (err) {
      let error: ConnectionTunnelErrorReason;
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
