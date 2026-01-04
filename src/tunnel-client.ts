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

const identity = Deno.args.includes("identity");
const credentials = Deno.args.includes("credentials");

if (!identity && !credentials) {
  throw new Error("must decide if credentials or identity auth");
}
if (identity && credentials) {
  throw new Error("can pick only credentials or identity");
}

const credentialsAuth = {
  mode: "credentials",
  identifier: "test",
  passkey: "test",
} satisfies TunnelRelayClientOptions["auth"];
const identityAuth = {
  mode: "identity",
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

  auth: identity ? identityAuth : credentialsAuth,
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
