import { Logger, prefixLogger } from "../../common/log.ts";
import { verifyCryptoKeyPair } from "../../common/security.ts";
import { TunnelServerError } from "../common/tunnel.errors.ts";
import { TunnelSecurityPermissions } from "../common/tunnel.security.ts";
import { createRelay, handleSocketRelay } from "./tunnel.relay.ts";

export type CreateTunnelRelayOptions = {
  listen: { port: number; hostname: string };
  signal: AbortSignal;

  performance: {
    decryptQueueSize: number;
  };

  auth: {
    credentials:
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

    identity:
      | { enabled: false }
      | {
        enabled: true;
        serverKeys: CryptoKeyPair;
        lookupClient: (hash: Uint8Array<ArrayBuffer>) => Promise<
          {
            key: CryptoKey;
            permissions: TunnelSecurityPermissions;
          } | undefined
        >;
      };
  };

  log: Logger;
};
export async function createTunnelRelayServer(
  options: CreateTunnelRelayOptions,
) {
  options.log.info(`creating tunnel relay server.`);

  if (options.signal.aborted) {
    options.log.warn(`given abort signal is already aborted, closing server.`);
    return;
  }

  options.log.debug(`validating configuration.`);
  if (options.auth.identity.enabled) {
    options.log.trace(`validating 'identity' authentication server key pair.`);
    const valid = await verifyCryptoKeyPair(
      options.auth.identity.serverKeys,
    );
    if (!valid) {
      throw new TunnelServerError({
        reason: "invalid-configuration",
        details: "server-keys",
      });
    }
  }

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

  options.log.debug(`creating relay context`);
  const relay = createRelay(options.log);

  options.log.debug(`creating server routes`);
  const relayRoutes: RelayRoute[] = [
    {
      pattern: new URLPattern({ pathname: "/admin" }),
      handle: () => {
        // TODO: implement admin dashboard that shows all connected sockets/services/connections
        return json({ todo: true });
      },
    },
    {
      pattern: new URLPattern({ pathname: "/relay" }),
      handle: (request) => {
        const { socket, response } = Deno.upgradeWebSocket(request);

        const socketId = crypto.randomUUID();
        const socketLog: Logger = prefixLogger(
          options.log,
          "[socket]",
          `[${socketId}]`,
        );

        socketLog.debug(`new socket connected.`);
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
            socketLog.error(`error handling socket.`, error);
          })
          .finally(() => {
            socketLog.trace(`socket done, cleaning up.`);
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
          options.log.error(
            "[http]",
            `error handling request '${request.url}'`,
            err,
          );
          return json({ error: "unhandled-error" }, { status: 500 });
        }
      }
      return json({ error: "not-found" }, { status: 404 });
    },
  );
  options.log.info(
    `http server listening on '${
      options.listen.hostname || "0.0.0.0"
    }:${options.listen.port}'.`,
  );
  await server.finished;
  options.log.info(`http server done.`);

  options.log.info(`wait for all remaining sockets to complete.`);
  await Promise.all([...allSockets]);
}
