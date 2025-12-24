import { gray, red, yellow } from "@std/fmt/colors";
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

const isClient = Deno.args.includes("client");
const isServer = Deno.args.includes("server");

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
  log: createLogger((level, content) => {
    let colorize: (str: string) => string;
    switch (level) {
      case "trace":
        colorize = gray;
        break;
      case "debug":
        colorize = yellow;
        break;
      case "error":
        colorize = red;
        break;
      default:
        colorize = (a) => a;
        break;
    }

    if (level === "trace") return;

    console.log(
      level,
      ...content.map((c) => typeof c === "string" ? colorize(c) : c),
    );
  }),
  signal: controller.signal,

  services: {
    proxyServer: isServer
      ? { enabled: true, service: "proxy" }
      : { enabled: false },
    proxyClient: isClient
      ? [{ service: "proxy", address: { port: 1080 } }]
      : [],
    bind: [],
    connect: [],
  },
});
