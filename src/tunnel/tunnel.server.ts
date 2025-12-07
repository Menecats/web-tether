import { Logger } from "../common/utils.ts";
import { createRelay, handleSocketRelay } from "./tunnel.relay.ts";
import { TunnelSecurityPermissions } from "./tunnel.security.ts";

export type CreateTunnelRelayOptions = {
  listen: { port: number; hostname: string };
  signal: AbortSignal;

  auth: {
    queueSize: number;

    basic:
      | { enabled: false }
      | {
        enabled: true;
        lookup: (
          identifier: string,
        ) => Promise<
          | {
            salt: Uint8Array<ArrayBuffer>;
            hash: Uint8Array<ArrayBuffer>;
            permissions: TunnelSecurityPermissions;
          }
          | undefined
        >;
      };

    advanced:
      | { enabled: false }
      | {
        enabled: true;
        lookupPrivateKey: () => Promise<CryptoKey>;
        lookupPublicKey: (
          identifier: Uint8Array<ArrayBuffer>,
        ) => Promise<
          {
            publicKey: CryptoKey;
            permissions: TunnelSecurityPermissions;
          } | undefined
        >;
      };
  };

  log: Logger;
};
export async function createTunnelRelay(options: CreateTunnelRelayOptions) {
  if (options.signal.aborted) return;

  const allSockets = new Set<ReturnType<typeof handleSocketRelay>>();

  type JsonOptions = {
    status?: number;
  };
  function json(body: unknown, { status = 200 }: JsonOptions = {}) {
    return new Response(JSON.stringify(body), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
      },
    });
  }

  type RelayRoute = {
    pattern: URLPattern;
    handle: (
      request: Request,
      match: URLPatternResult,
    ) => Response | Promise<Response>;
  };

  const relay = createRelay();

  const relayRoutes: RelayRoute[] = [
    {
      pattern: new URLPattern({ pathname: "/admin" }),
      handle: () => {
        // TODO
        return json({ todo: true });
      },
    },
    {
      pattern: new URLPattern({ pathname: "/relay" }),
      handle: (request) => {
        const { socket, response } = Deno.upgradeWebSocket(request);

        const socketId = crypto.randomUUID();
        const socketLog: Logger = (level, ...content) =>
          options.log(level, `[${socketId}]:`, ...content);

        socketLog("debug", `New socket.`);
        const socketDone = handleSocketRelay(
          { ...options, log: socketLog },
          socket,
          relay,
        );

        // Register active connection
        allSockets.add(socketDone);

        // Once done deregister active connection
        socketDone
          .catch((error) => {
            socketLog(
              "error",
              `Error while handling socket.`,
              error,
            );
          })
          .finally(() => {
            socketLog("trace", `Purging socket.`);
            allSockets.delete(socketDone);
          });

        return response;
      },
    },
  ];

  const server = Deno.serve(
    { ...options.listen, signal: options.signal },
    (request) => {
      for (const route of relayRoutes) {
        const result = route.pattern.exec(request.url);
        if (!result) continue;

        try {
          return route.handle(request, result);
        } catch (err) {
          options.log(
            "error",
            `Error while handling request '${request.url}'`,
            err,
          );
          return json({ error: "unhandled-error" }, { status: 500 });
        }
      }
      return json({ error: "not-found" }, { status: 404 });
    },
  );
  await server.finished;

  await Promise.all([...allSockets]);
}
