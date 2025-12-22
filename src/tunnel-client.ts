import { createLogger } from "./common/log.ts";
import { client, server } from "./common/test-keys.ts";
import { createTunnelRelayClient } from "./tunnel/tunnel.client.ts";
import { TunnelClientError } from "./tunnel/tunnel.errors.ts";

const controller = new AbortController();

Deno.addSignalListener("SIGINT", () => {
  console.log("interrupt");
  controller.abort(new TunnelClientError({ reason: "application-aborted" }));
});

const username = "test";
const password = "test";

await createTunnelRelayClient({
  endpoint: new URL("ws://localhost:3456/relay"),

  performance: {
    connectionHandleTimeout: 1000,
    decryptQueueSize: 1024,
    reconnectDelay: (context) => 5000,
  },

  auth: {
    mode: "advanced",
    serverKey: server.publicKey,
    clientKeys: client,
  },
  log: createLogger((level, content) => console.log(level, ...content)),
  signal: controller.signal,

  services: {
    proxyServer: { enabled: true, service: "proxy" },
    proxyClient: [
      { service: "proxy", address: { port: 1080 } },
    ],
    bind: [],
    connect: [],
  },
});
