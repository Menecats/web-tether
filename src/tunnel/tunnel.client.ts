import { delay } from "@std/async/delay";
import { asyncAction } from "../common/async.ts";
import {
  ConnectionTunnel,
  ConnectionTunnelErrorReason,
  createConnectionTunnelPair,
} from "../common/communication.ts";
import { Logger, prefixLogger } from "../common/log.ts";
import { safeReader } from "../common/safe-buffer.ts";
import { verifyCryptoKeyPair } from "../common/security.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
  derivedSignal as deriveSignal,
  safelyClose,
} from "../common/utils.ts";
import {
  SocksDestinationAddress,
  SocksTunnelResponse,
} from "../proxy/socks.common.ts";
import { createSocksServer } from "../proxy/socks.server.ts";
import { handleAdvancedAuthenticationClient } from "./auth/client/advanced-authentication.client.ts";
import { handleBasicAuthenticationClient } from "./auth/client/basic-authentication.client.ts";
import { TunnelClientError } from "./tunnel.errors.ts";
import { RelayCommand } from "./tunnel.relay.ts";

async function validateConfiguration(options: TunnelRelayClientOptions) {
  if (options.auth.mode === "advanced") {
    const valid = await verifyCryptoKeyPair(
      options.auth.clientKeys,
    );
    if (!valid) {
      throw new TunnelClientError({
        reason: "invalid-configuration",
        details: "client-keys",
      });
    }
  }

  const boundServices: string[] = [
    options.services.proxyServer.enabled
      ? [options.services.proxyServer.service]
      : [],
    options.services.bind.map((v) => v.service),
  ].flat();
  const duplicateServices = [
    ...boundServices
      .reduce<Map<string, number>>((accumulated, service) => {
        accumulated.set(service, (accumulated.get(service) || 0) + 1);
        return accumulated;
      }, new Map())
      .entries(),
  ].filter(([, count]) => count > 1).map(([service]) => service);
  if (duplicateServices.length) {
    throw new TunnelClientError({
      reason: "invalid-configuration",
      details: "duplicate-bound-services",
    });
  }

  const boundAddresses: Deno.TcpListenOptions[] = [
    options.services.proxyClient.map((c) => c.address),
    options.services.connect.map((c) => c.source),
  ].flat();
  const duplicatePorts = [
    ...boundAddresses
      .reduce<Map<number, number>>(
        (accumulated, address) => {
          accumulated.set(
            address.port,
            (accumulated.get(address.port) || 0) + 1,
          );
          return accumulated;
        },
        new Map(),
      )
      .entries(),
  ].filter(([, count]) => count > 1).map(([port]) => port);
  if (duplicatePorts.length) {
    throw new TunnelClientError({
      reason: "invalid-configuration",
      details: "duplicate-bound-addresses",
    });
  }
}

type HandledProxy = {
  expired: boolean;

  readonly destination: SocksDestinationAddress;
  readonly log: Logger;

  readonly emit: (tunnel: SocksTunnelResponse) => void;
};
type ListeningProxy = {
  proxy: TunnelRelayClientOptions["services"]["proxyClient"][number];
  handle: ConsumableAsyncQueue<HandledProxy>;
  done: Promise<void>;
};

type HandledConnection = {
  expired: boolean;

  readonly connection: Deno.TcpConn;
  readonly log: Logger;
};
type ListeningConnection = {
  connection: TunnelRelayClientOptions["services"]["connect"][number];
  handle: ConsumableAsyncQueue<HandledConnection>;
  done: Promise<void>;
};

export type TunnelRelayClientOptions = {
  endpoint: URL;
  signal: AbortSignal;

  performance: {
    decryptQueueSize: number;
    connectionHandleTimeout: number;
    reconnectDelay: (context: { attempts: number; valid: boolean }) => number;
  };

  auth:
    | {
      mode: "basic";
      identifier: string;
      passkey: string;
    }
    | {
      mode: "advanced";
      serverKey: CryptoKey;
      clientKeys: CryptoKeyPair;
    };

  services: {
    proxyServer:
      | { enabled: false }
      | { enabled: true; service: string };
    proxyClient: {
      service: string;
      address: Deno.TcpListenOptions;
    }[];
    bind: {
      service: string;
      destination: Omit<Deno.ConnectOptions, "signal">;
    }[];
    connect: {
      service: string;
      source: Deno.TcpListenOptions;
    }[];
  };

  log: Logger;
};
export async function createTunnelRelayClient(
  options: TunnelRelayClientOptions,
) {
  options.log.debug("validate configuration");
  await validateConfiguration(options);

  // TODO: Create local listeners

  options.log.debug("create proxy client listeners");
  const listeningProxies = options.services
    .proxyClient
    .map((proxy): ListeningProxy => {
      const handle = consumableAsyncQueue<HandledProxy>({
        signal: options.signal,
      });

      const server = createSocksServer({
        listen: proxy.address,
        signal: options.signal,
        socks4: { enabled: true, auth: { enabled: false } },
        socks5: { enabled: true, auth: { enabled: false } },
        log: prefixLogger(options.log, `[proxy-client:${proxy.service}]`),
        tunnel: async (destination, log) => {
          if (handle.aborted()) throw handle.abortReason();

          const result = Promise.withResolvers<SocksTunnelResponse>();

          const connection: HandledProxy = {
            expired: false,

            destination,
            log,

            emit: result.resolve,
          };

          const handleTimeout = setTimeout(() => {
            result.reject(new TunnelClientError({ reason: "timeout" }));
            connection.expired = true;
          }, options.performance.connectionHandleTimeout);

          handle.push(connection, {
            onAborted: (reason) => result.reject(reason),
            onDequeue: () => clearTimeout(handleTimeout),
          });

          return await result.promise;
        },
      });

      return { proxy, handle, done: server };
    });

  const listeningConnections = options.services
    .connect
    .map((connection): ListeningConnection => {
      const log = prefixLogger(
        options.log,
        `[connect-client:${connection.service}]`,
      );

      const handle = consumableAsyncQueue<HandledConnection>({
        signal: options.signal,
      });

      const done = (async () => {
        log.info("Starting server");
        const listener = Deno.listen(connection.source);

        const closeListener = () => listener.close();
        options.signal.addEventListener("abort", closeListener, { once: true });

        log.info("Listening for connections");
        try {
          for await (const connection of listener) {
            if (handle.aborted()) {
              log.info("got connection but already aborted, closing it");
              connection.close();
              continue;
            }

            log.debug("got connection");

            const handledConnection: HandledConnection = {
              expired: false,
              connection,
              log,
            };

            const handleTimeout = setTimeout(() => {
              connection.close();
              handledConnection.expired = true;
            }, options.performance.connectionHandleTimeout);

            handle.push(handledConnection, {
              onAborted: () => connection.close(),
              onDequeue: () => clearTimeout(handleTimeout),
            });
          }
        } finally {
          options.signal.removeEventListener("abort", closeListener);
        }
      })();

      return { connection, handle, done };
    });

  let connectedOnce = false;
  let failed = 0;

  while (!options.signal.aborted) {
    if (failed) {
      const waitDelay = options.performance.reconnectDelay({
        attempts: failed,
        valid: connectedOnce,
      });

      options.log.debug(
        `delay connection after #${failed} failed attempt(s), waiting ${waitDelay}ms`,
      );

      await delay(waitDelay, { signal: options.signal });
    }

    options.log.debug(`connecting to '${options.endpoint}'`);

    const log = prefixLogger(options.log, "[socket]");

    const socket = new WebSocket(options.endpoint);
    socket.binaryType = "arraybuffer";

    const socketAbort = deriveSignal(options.signal);

    try {
      await handleSocket({
        socket,
        options: options,
        signal: socketAbort.signal,
        log,
        connected: () => {
          connectedOnce = true;
          failed = 0;
        },

        services: {
          proxies: listeningProxies,
          connections: listeningConnections,
        },
      });
    } catch (err) {
      log.error("error handling socket", err);
      failed++;
    } finally {
      socket.close();
      socketAbort.abort(new TunnelClientError({ reason: "socket-closed" }));
    }
  }
}

type HandleSocketOptions = {
  socket: WebSocket;
  options: Omit<TunnelRelayClientOptions, "log" | "signal">;
  signal: AbortSignal;
  log: Logger;
  connected: () => void;

  services: {
    proxies: ListeningProxy[];
    connections: ListeningConnection[];
  };
};
async function handleSocket({
  socket,
  options,
  signal: socketSignal,
  log,
  connected: notifyConnected,
  services,
}: HandleSocketOptions) {
  using queue = consumableAsyncQueue<ArrayBuffer>({ signal: socketSignal });
  const ready = Promise.withResolvers<void>();

  log.trace(`configuring 'ready' listeners`);

  socket.onmessage = ({ data }) => {
    if (data instanceof ArrayBuffer) queue.push(data);
  };
  socket.onopen = () =>
    queue.aborted() ? ready.reject(queue.abortReason()) : ready.resolve();
  socket.onclose = () =>
    ready.reject(new TunnelClientError({ reason: "socket-closed" }));
  socket.onerror = (event) =>
    ready.reject(
      new TunnelClientError({
        reason: "socket-error",
        error: ("error" in event) ? event.error : event,
      }),
    );

  log.trace(`waiting for socket to connect`);
  await ready.promise;
  log.debug(`connected`);

  log.trace(`configuring 'abort' listeners`);
  socket.onopen = null;
  socket.onclose = () =>
    queue.abortWith(new TunnelClientError({ reason: "socket-closed" }));
  socket.onerror = (event) =>
    queue.abortWith(
      new TunnelClientError({
        reason: "socket-error",
        error: ("error" in event) ? event.error : event,
      }),
    );

  log.trace(`perform handshake`);
  const security = options.auth.mode === "basic"
    ? await handleBasicAuthenticationClient(
      socket,
      queue,
      options.auth,
      prefixLogger(log, "[basic]"),
    )
    : await handleAdvancedAuthenticationClient(
      socket,
      queue,
      options.auth,
      prefixLogger(log, "[advanced]"),
    );

  notifyConnected();

  log.trace(`configure decrypted queue`);
  using decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>({
    signal: socketSignal,
    map: (packet, queueSignal) => security.decrypt(packet, queueSignal),
  });

  asyncAction(async (actionSignal) => {
    try {
      while (!actionSignal.aborted) {
        const encryptedPacket = await queue.shift({ signal: actionSignal });
        if (decryptQueue.queued() >= options.performance.decryptQueueSize) {
          await decryptQueue.waitFor("dequeue", { signal: actionSignal });
        }

        if (!actionSignal.aborted) {
          decryptQueue.push(encryptedPacket);
        }
      }
    } catch (error) {
      if (!queue.aborted()) {
        queue.abortWith(
          (error instanceof TunnelClientError)
            ? error
            : new TunnelClientError({ reason: "unknown-error", error }),
        );
      }

      decryptQueue.abortWith(queue.abortReason());
    }
  }, { signal: socketSignal });

  let localUID = 1;

  const serviceConnections = new Map<number, {
    connected: boolean;

    readonly uid: number;
    readonly tunnel: ConnectionTunnel;

    readonly onConnect?: () => void;
    readonly onError?: (reason: ConnectionTunnelErrorReason) => void;
  }>();

  try {
    services.proxies.forEach((proxy) =>
      asyncAction(async (actionSignal) => {
        while (!actionSignal.aborted) {
          const request = await proxy.handle.shift({ signal: actionSignal });
          if (request.expired || actionSignal.aborted) continue;

          const uid = localUID++;

          const requestLog = prefixLogger(request.log, `[${uid}]`);
          requestLog.trace(`creating connection`);

          const [relayTunnel, proxyTunnel] = createConnectionTunnelPair();

          serviceConnections.set(uid, {
            connected: false,

            uid,
            tunnel: relayTunnel,

            onConnect: () => {
              requestLog.trace(`connected`);
              request.emit({ ok: true, tunnel: proxyTunnel });
            },
            onError: (reason) => {
              requestLog.trace(`connection failed due to '${reason}'`);
              request.emit({ ok: false, error: reason });
            },
          });

          // TODO: Send connect request
        }
      }, { signal: socketSignal })
    );
    services.connections.forEach((connection) =>
      asyncAction(async (actionSignal) => {
        while (!actionSignal.aborted) {
          const request = await connection.handle.shift({
            signal: actionSignal,
          });
          if (request.expired || actionSignal.aborted) continue;

          const uid = localUID++;

          const requestLog = prefixLogger(request.log, `[${uid}]`);
          requestLog.trace(`creating connection`);

          serviceConnections.set(uid, {
            connected: false,

            uid,
            tunnel: request.connection,

            onConnect: () => {
              requestLog.trace(`connected`);
            },
            onError: (reason) => {
              requestLog.trace(`connection failed due to '${reason}'`);
            },
          });

          // TODO: Send connect request
        }
      }, { signal: socketSignal })
    );

    log.trace(`ready, waiting commands`);
    while (!socketSignal.aborted) {
      const buffer = safeReader(
        await decryptQueue.shift(),
        () => new TunnelClientError({ reason: "buffer-too-short" }),
      );

      const command = buffer.uint8();

      switch (command) {
        case RelayCommand.SOCKET_CLOSE: {
          log.debug(`received close command`);
          socket.send(new Uint8Array([RelayCommand.SOCKET_CLOSE]));
          return;
        }

          // TODO: Handle all commands
      }
    }
  } finally {
    serviceConnections.forEach((connection) => {
      if (!connection.connected) connection.onError?.("general-failure");
      safelyClose(connection.tunnel);
    });
  }
}
