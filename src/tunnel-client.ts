import { colorizeOutput, createLogger } from "./common/log.ts";
import { client, server } from "./common/test-keys.ts";
import { createTunnelRelayClient } from "./tunnel/client/tunnel.client.ts";
import { TunnelRelayClientOptions } from "./tunnel/common/tunnel.common.types.ts";
import { TunnelClientError } from "./tunnel/common/tunnel.errors.ts";

const controller = new AbortController();

Deno.addSignalListener("SIGINT", () => {
  console.log("interrupt");
  controller.abort(new TunnelClientError({ reason: "application-aborted" }));
});

const isClient = Deno.args.includes("client");
const isServer = Deno.args.includes("server");

const advanced = Deno.args.includes("advanced");
const basic = Deno.args.includes("basic");

if (!advanced && !basic) {
  throw new Error("must decide if basic or advanced auth");
}
if (advanced && basic) {
  throw new Error("can pick only basic or advanced");
}

const basicAuth = {
  mode: "basic",
  identifier: "test",
  passkey: "test",
} satisfies TunnelRelayClientOptions["auth"];
const advancedAuth = {
  mode: "advanced",
  serverKey: server.publicKey,
  clientKeys: client,
} satisfies TunnelRelayClientOptions["auth"];

await createTunnelRelayClient({
  endpoint: new URL("ws://localhost:3456/relay"),

  performance: {
    connectionHandleTimeout: 1000,
    decryptQueueSize: 1024,
    reconnectDelay: (context) => 5000,
  },

  auth: advanced ? advancedAuth : basicAuth,
  log: createLogger(colorizeOutput(console.log)),
  signal: controller.signal,

  services: {
    proxyServer: isServer
      ? { enabled: true, service: "proxy" }
      : { enabled: false },
    proxyClient: isClient
      ? {
        enabled: true,
        address: { port: 1080 },
        destination: (request) => {
          return {
            type: "relay",
            destination: request,
            service: "proxy",
          };
        },
      }
      : { enabled: false },
    bind: [],
    connect: [],
  },
});
