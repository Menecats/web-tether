import { createLogger } from "./common/log.ts";
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
    decryptQueueSize: 1024,
    reconnectDelay: (context) => 5000,
  },

  auth: {
    mode: "basic",
    identifier: username,
    passkey: password,
  },
  log: createLogger((level, content) => console.log(level, ...content)),
  signal: controller.signal,
});
