import { delay } from "@std/async/delay";
import { asyncAction } from "../common/async.ts";
import {
  ConnectionTunnel,
  ConnectionTunnelErrorReason,
  createConnectionTunnelPair,
} from "../common/communication.ts";
import { Logger, prefixLogger } from "../common/log.ts";
import {
  encodeInt32,
  encodeUint16,
  encodeWithUint16Length,
  safeReader,
} from "../common/safe-buffer.ts";
import { verifyCryptoKeyPair } from "../common/security.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
  deriveSignal,
  printEnum,
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
import {
  RelayBindReply,
  RelayCommand,
  RelayConnectReply,
  RelayLinkReply,
  RelayServiceType,
} from "./tunnel.relay.ts";

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

  try {
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
      } catch (error) {
        log.error("error handling socket", error);
        socketAbort.abort(error);
        failed++;
      } finally {
        socket.close();
        if (!socketAbort.signal.aborted) {
          socketAbort.abort(new TunnelClientError({ reason: "socket-closed" }));
        }
      }
    }
  } catch (err) {
    options.log.error("error while handling connection loop", err);
  }
  options.log.trace("connection loop done");
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

  const write = (content: Uint8Array<ArrayBuffer> | ArrayBuffer) =>
    security.encrypt(content, socketSignal).then((buffer) =>
      socket.send(buffer)
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

  const registeredServices = new Map<
    string,
    | {
      service: string;
      type: RelayServiceType.RAW_SOCKET;
      destination: Omit<Deno.ConnectOptions, "signal">;
    }
    | { service: string; type: RelayServiceType.SOCKS_PROXY }
  >();

  if (options.services.proxyServer.enabled) {
    registeredServices.set(options.services.proxyServer.service, {
      service: options.services.proxyServer.service,
      type: RelayServiceType.SOCKS_PROXY,
    });
  }
  options.services.bind.forEach((bind) => {
    registeredServices.set(bind.service, {
      service: bind.service,
      type: RelayServiceType.RAW_SOCKET,
      destination: bind.destination,
    });
  });

  const serviceConnections = new Map<number, {
    connected: boolean;

    readonly uid: number;
    readonly tunnel: ConnectionTunnel;

    readonly onConnect?: () => void;
    readonly onError?: (reason: ConnectionTunnelErrorReason) => void;
  }>();
  const serviceLinks = new Map<number, {
    // TODO: service links type
  }>();

  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  try {
    services.proxies.forEach((proxy) => {
      const serviceLog = prefixLogger(log, `[${proxy.proxy.service}]`);
      const encodedService = encodeWithUint16Length(
        encoder.encode(proxy.proxy.service),
      );
      asyncAction(async (actionSignal) => {
        try {
          while (!actionSignal.aborted) {
            serviceLog.trace("waiting for proxy connection");

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

            try {
              requestLog.trace(`sending connection request`);
              await write(
                new Uint8Array([
                  RelayCommand.SERVICE_CONNECT,
                  ...encodeInt32(uid),
                  RelayServiceType.SOCKS_PROXY,
                  ...encodedService,
                  ...encodeWithUint16Length(
                    encoder.encode(request.destination.host),
                  ),
                  ...encodeUint16(request.destination.port),
                ]),
              );
            } catch (error) {
              requestLog.error(`error sending connection request`, error);
            }
          }
        } catch (err) {
          serviceLog.error("error while listening service", err);
        }
      }, { signal: socketSignal });
    });
    services.connections.forEach((connection) => {
      const serviceLog = prefixLogger(
        log,
        `[${connection.connection.service}]`,
      );
      const encodedService = encodeWithUint16Length(
        encoder.encode(connection.connection.service),
      );
      asyncAction(async (actionSignal) => {
        try {
          while (!actionSignal.aborted) {
            serviceLog.trace("waiting for raw connection");
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

            await write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodeInt32(uid),
                RelayServiceType.RAW_SOCKET,
                ...encodedService,
              ]),
            );
          }
        } catch (err) {
          serviceLog.error("error while listening service", err);
        }
      }, { signal: socketSignal });
    });

    {
      await write(
        new Uint8Array([
          RelayCommand.SERVICE_BIND,
          ...encodeUint16(registeredServices.size),
          ...[...registeredServices.values()].flatMap((binding) => [
            binding.type,
            ...encodeWithUint16Length(encoder.encode(binding.service)),
          ]),
        ]),
      );
    }

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
          await write(new Uint8Array([RelayCommand.SOCKET_CLOSE]));
          return;
        }

        case RelayCommand.SERVICE_BIND: {
          const reply = buffer.uint8();
          if (reply === RelayBindReply.SUCCESS) {
            log.debug("bind successful");
          } else {
            log.error(`bind errored: ${printEnum(RelayBindReply, reply)}`);
          }
          break;
        }

        case RelayCommand.SERVICE_CONNECT: {
          log.trace(`received connect response`);

          const uid = buffer.int32();
          const reply = buffer.uint8();

          log.trace(
            `connect [${uid}]: ${printEnum(RelayConnectReply, reply)}`,
          );

          const service = serviceConnections.get(uid);
          if (service) {
            if (reply === RelayConnectReply.SUCCESS) {
              service.connected = true;
              service.onConnect?.();
            } else if (!service.connected) {
              let reason: ConnectionTunnelErrorReason;

              switch (reply) {
                case RelayConnectReply.CONNECT_NOT_ALLOWED:
                  reason = "not-allowed";
                  break;
                case RelayConnectReply.CONNECT_NETWORK_UNREACHABLE:
                  reason = "network-unreachable";
                  break;
                case RelayConnectReply.CONNECT_HOST_UNREACHABLE:
                  reason = "host-unreachable";
                  break;
                case RelayConnectReply.CONNECT_CONNECTION_REFUSED:
                  reason = "connection-refused";
                  break;
                case RelayConnectReply.CONNECT_TTL_EXPIRED:
                  reason = "ttl-expired";
                  break;
                default:
                  reason = "general-failure";
              }

              service.onError?.(reason);
            }
          }
          break;
        }

        case RelayCommand.SERVICE_LINK: {
          const encodedUID = buffer.data(4, { ahead: true });
          const uid = buffer.int32();
          const name = decoder.decode(buffer.data(buffer.uint16()));

          if (uid >= 0 || serviceLinks.has(uid)) {
            log.trace(`recevied link request, but has an invalid identifier`);
            await write(
              new Uint8Array([
                RelayCommand.SERVICE_LINK,
                ...encodedUID,
                RelayLinkReply.SERVICE_INVALID_IDENTIFIER,
              ]),
            );
            break;
          }

          const service = registeredServices.get(name);
          if (!service) {
            log.trace(`recevied link request, but the service is not known`);
            await write(
              new Uint8Array([
                RelayCommand.SERVICE_LINK,
                ...encodedUID,
                RelayLinkReply.SERVICE_NOT_FOUND,
              ]),
            );
          } else {
            log.trace(`new link request [${uid}] for service ${name}`);

            // TODO: create tunnel connection
          }

          break;
        }

        case RelayCommand.SERVICE_CLOSED: {
          const uid = buffer.int32();
          const reason = buffer.uint8();

          // TODO: Handle service closed
          break;
        }
        case RelayCommand.SERVICE_STREAM: {
          const uid = buffer.int32();
          const data = buffer.dataLeft();

          if (uid > 0) {
            const connection = serviceConnections.get(uid);
            if (!connection) {
              // TODO: notify connection gone
            } else {
              const writer = connection.tunnel.writable.getWriter();
              await writer.write(data);
              writer.releaseLock();
            }
          } else if (uid < 0) {
            const connection = serviceLinks.get(uid);
            if (!connection) {
              // TODO: notify connection gone
            } else {
              // TODO: Write
            }
          }
          // TODO: Handle service stream
          break;
        }

        case RelayCommand.UNSUPPORTED: {
          const unsupportedCommand = buffer.uint8();
          log.error(
            `server notified unsupported command: ${
              printEnum(RelayCommand, unsupportedCommand)
            }`,
          );
          break;
        }

        default: {
          log.warn(
            `received unsupported command: ${printEnum(RelayCommand, command)}`,
          );
          await write(new Uint8Array([RelayCommand.UNSUPPORTED, command]));
          break;
        }
      }
    }
  } finally {
    log.trace(`closing connections before termination`);
    serviceConnections.forEach((connection) => {
      if (!connection.connected) connection.onError?.("general-failure");
      safelyClose(connection.tunnel);
    });
  }
}
