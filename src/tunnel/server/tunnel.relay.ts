import {
  createCipheredWriter,
  createDecipheredQueue,
} from "../../common/communication.ts";
import { Logger, prefixLogger } from "../../common/log.ts";
import {
  encodeInt32,
  encodeWithUint16Length,
  safeReader,
} from "../../common/safe-buffer.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
  printEnum,
  safelyClose,
} from "../../common/utils.ts";
import { TunnelWriter } from "../common/tunnel.common.types.ts";
import { RelayAuthentication, RelayVersion7 } from "../common/tunnel.const.ts";
import { TunnelServerError } from "../common/tunnel.errors.ts";
import { TunnelSecurity } from "../common/tunnel.security.ts";
import { handleCredentialsAuthenticationServer } from "./auth/credentials-authentication.server.ts";
import { handleAdvencedAuthenticationServer } from "./auth/identity-authentication.server.ts";
import type { CreateTunnelRelayOptions } from "./tunnel.server.ts";

export enum RelayBindReply {
  SUCCESS = 0x01,
  SOCKET_ALREADY_BOUND = 0x30,
  SERVICE_ALREADY_BOUND = 0x31,
  SERVICE_INVALID_TYPE = 0x32,
  UNAUTHORIZED = 0xfe,
}
export enum RelayConnectReply {
  SUCCESS = 0x00,

  CONNECT_GENERAL_FAILURE = 0x10,
  CONNECT_NOT_ALLOWED = 0x11,
  CONNECT_NETWORK_UNREACHABLE = 0x12,
  CONNECT_HOST_UNREACHABLE = 0x13,
  CONNECT_CONNECTION_REFUSED = 0x14,
  CONNECT_TTL_EXPIRED = 0x15,

  SERVICE_INVALID_TYPE = 0x32,
  SERVICE_NOT_FOUND = 0x33,
  SERVICE_INVALID_IDENTIFIER = 0x34,
  SERVICE_UNAUTHORIZED = 0xfe,
}
export enum RelayLinkReply {
  SUCCESS = 0x00,

  CONNECT_GENERAL_FAILURE = 0x10,
  CONNECT_NOT_ALLOWED = 0x11,
  CONNECT_NETWORK_UNREACHABLE = 0x12,
  CONNECT_HOST_UNREACHABLE = 0x13,
  CONNECT_CONNECTION_REFUSED = 0x14,
  CONNECT_TTL_EXPIRED = 0x15,

  SERVICE_NOT_FOUND = 0x33,
  SERVICE_INVALID_IDENTIFIER = 0x34,
}

export enum RelayCommand {
  SOCKET_CLOSE = 0x00,

  SERVICE_BIND = 0x10,
  SERVICE_CONNECT = 0x11,
  SERVICE_STREAM = 0x12,
  SERVICE_LINK = 0x13,
  SERVICE_CLOSED = 0x14,

  UNSUPPORTED = 0xff,
}

export enum RelayServiceType {
  RAW_SOCKET = 0x00,
  SOCKS_PROXY = 0x01,
}

export type RelayService = {
  type: RelayServiceType;
  service: string;
};

export enum RelayServiceConnectionReason {
  TRANSPORT_SOCKET_EOS = 0x00,
  TRANSPORT_SOCKET_INTERRUPTED = 0x02,
  TRANSPORT_SOCKET_CLOSED = 0x03,
  TRANSPORT_FORWARD_FAILED = 0x04,
  TRANSPORT_SOCKET_START_FAILED = 0x05,
  CONNECTION_GONE = 0xfe,
  UNKNOWN = 0xff,
}
export type RelayServiceConnection = {
  readonly server: {
    socket: WebSocket;
    uid: number;
    write: TunnelWriter;
  };
  readonly client: {
    socket: WebSocket;
    uid: number;
    write: TunnelWriter;
  };

  notify: (source: WebSocket, reply: RelayLinkReply) => void;
  close(source: WebSocket, reason: RelayServiceConnectionReason): void;
  forward(source: WebSocket, buffer: Uint8Array<ArrayBuffer>): void;
};

export type Relay = {
  service: (service: string) => RelayServiceType | undefined;
  bind: (socket: WebSocket, services: RelayService[]) => void;

  connection: (
    socket: WebSocket,
    uid: number,
  ) => RelayServiceConnection | undefined;
  link: (
    socket: WebSocket,
    service: string,
    uid: number,
    metadata: Uint8Array<ArrayBuffer>,
  ) => void;

  connected: (socket: WebSocket, write: TunnelWriter) => void;
  disconnected: (socket: WebSocket) => void;
};

async function authenticateRelay(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayOptions["auth"],
  log: Logger,
): Promise<TunnelSecurity<"relay"> | undefined> {
  log.debug(`waiting for client handshake.`);
  const packet = safeReader(
    await queue.shift({
      timeout: 1000, // TODO
      timeoutError: () => new TunnelServerError({ reason: "timeout" }),
    }),
    () => new TunnelServerError({ reason: "buffer-too-short" }),
  );

  const version = packet.uint8();
  if (version !== RelayVersion7) {
    throw new TunnelServerError({ reason: "unknown-version", version });
  }

  const authMode = packet.uint8();
  log.trace(`using appropriate authenticaiton schema.`);

  if (authMode === RelayAuthentication.BASIC_AUTH) {
    if (auth.credentials.enabled) {
      return await handleCredentialsAuthenticationServer(
        socket,
        queue,
        auth.credentials,
        packet,
        prefixLogger(log, "[credentials]"),
      );
    } else {
      socket.send(
        new Uint8Array([RelayVersion7, RelayAuthentication.UNSUPPORTED_AUTH]),
      );
      return undefined;
    }
  }

  if (authMode === RelayAuthentication.ADVANCED_AUTH) {
    if (auth.identity.enabled) {
      return await handleAdvencedAuthenticationServer(
        socket,
        queue,
        auth.identity,
        packet,
        prefixLogger(log, "[identity]"),
      );
    } else {
      socket.send(
        new Uint8Array([RelayVersion7, RelayAuthentication.UNSUPPORTED_AUTH]),
      );
      return undefined;
    }
  }

  socket.send(
    new Uint8Array([RelayVersion7, RelayAuthentication.UNSUPPORTED_AUTH]),
  );
  return undefined;
}

export type RelayFailure =
  | "bind-unauthorized"
  | "bind-already-bound-socket"
  | "bind-invalid-service-type"
  | "bind-unauthorized-services"
  | "bind-already-bound-services"
  | "connect-unauthorized"
  | "connect-invalid-uid"
  | "connect-invalid-service-type"
  | "connect-unauthorized-service"
  | "connect-service-not-found"
  | "connect-non-matching-service-type"
  | "unsupported-command";

// TODO: check wether blocking features are something necessary?
function isBlockingFailure(operation: RelayFailure): boolean {
  switch (operation) {
    case "bind-unauthorized":
    case "bind-already-bound-socket":
    case "bind-invalid-service-type":
    case "bind-unauthorized-services":
    case "bind-already-bound-services":
    case "connect-unauthorized":
    case "connect-invalid-uid":
    case "connect-invalid-service-type":
    case "connect-unauthorized-service":
    case "unsupported-command":
      return true;

    case "connect-service-not-found":
    case "connect-non-matching-service-type":
      return false;
  }
}

export async function handleSocketRelay(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
  relay: Relay,
) {
  try {
    using queue = consumableAsyncQueue<ArrayBuffer>({ signal: options.signal });
    const ready = Promise.withResolvers<void>();

    options.log.trace(`configuring 'ready' listeners.`);

    socket.binaryType = "arraybuffer";
    socket.onmessage = ({ data }) => {
      if (data instanceof ArrayBuffer) queue.push(data);
    };
    socket.onopen = () => {
      if (queue.aborted()) {
        options.log.debug(
          "[listener]",
          "socket connection opened, but queue is already aborted, rejecting.",
          queue.abortReason(),
        );
        ready.reject(queue.abortReason());
      } else {
        options.log.debug(
          "[listener]",
          "socket connection opened, notifying ready.",
        );
        ready.resolve();
      }
    };
    socket.onclose = () => {
      options.log.debug(
        "[listener]",
        "socket connection closed before being opened, rejecting.",
      );
      ready.reject(new TunnelServerError({ reason: "socket-closed" }));
    };
    socket.onerror = (event) => {
      options.log.debug(
        "[listener]",
        "socket connection errored before being opened, rejecting.",
      );
      ready.reject(
        new TunnelServerError({
          reason: "socket-error",
          error: "error" in event ? event.error : event,
        }),
      );
    };

    options.log.debug(`waiting for socket connection to open.`);
    await ready.promise;

    options.log.trace(`configuring 'abort' listeners.`);
    socket.onopen = null;
    socket.onclose = () => {
      options.log.debug(`[listener]`, `connection closed, aborting queue.`);
      queue.abortWith(new TunnelServerError({ reason: "socket-closed" }));
    };
    socket.onerror = (event) => {
      let error = "error" in event ? event.error : event;

      // Normalize 'UnexpectedEof' error if necessary
      if (
        "message" in event && event.message === "Unexpected EOF" &&
        !(error instanceof Deno.errors.UnexpectedEof)
      ) {
        error = new Deno.errors.UnexpectedEof();
      }

      options.log.debug(`[listener]`, `connection errored, aborting queue.`);
      queue.abortWith(new TunnelServerError({ reason: "socket-error", error }));
    };

    const security = await authenticateRelay(
      socket,
      queue,
      options.auth,
      prefixLogger(options.log, "[auth]"),
    );

    if (!security) {
      options.log.debug(`authentication failed`);
      return;
    }

    options.log.trace(`configure cipher writer and decrypted queue`);
    const writer = createCipheredWriter({
      socket,
      security,
      signal: options.signal,
      log: options.log,
    });
    using decryptQueue = createDecipheredQueue({
      cipheredQueue: queue,
      security,
      signal: options.signal,
      decryptQueueSize: options.performance.decryptQueueSize,
    });

    const decoder = new TextDecoder();
    let serviceBound = false;

    relay.connected(socket, writer.write);

    options.log.info(`[auth:${security.alias}]`, `ready, waiting commands`);
    while (!options.signal.aborted) {
      const buffer = safeReader(
        await decryptQueue.shift(),
        () => new TunnelServerError({ reason: "buffer-too-short" }),
      );

      const command = buffer.uint8();

      switch (command) {
        case RelayCommand.SOCKET_CLOSE: {
          options.log.debug(`received close command`);
          writer.write(new Uint8Array([RelayCommand.SOCKET_CLOSE]));
          return;
        }

        case RelayCommand.SERVICE_BIND: {
          if (!security.permissions.bind.enabled) {
            options.log.trace(`received bind request, but bind is not allowed`);
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("bind-unauthorized")) return;
            else break;
          }

          if (serviceBound) {
            options.log.trace(
              `received bind request, but socket is already bound`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.SOCKET_ALREADY_BOUND,
              ]),
            );
            if (isBlockingFailure("bind-already-bound-socket")) return;
            else break;
          }
          serviceBound = true;

          const servicesCount = buffer.uint16();

          let someUnavailable = false;
          let someUnauthorized = false;
          let someInvalidService = false;

          const services: RelayService[] = [];

          for (let i = 0; i < servicesCount; ++i) {
            const serviceType = buffer.uint8();

            const service = buffer.data(buffer.uint16());

            const serviceName = decoder.decode(service);

            if (!(serviceType in RelayServiceType)) {
              someInvalidService = true;
              continue;
            }

            const allowed = await security.permissions.bind.allowed(
              serviceName,
            );
            if (!allowed) {
              someUnauthorized = true;
              continue;
            }

            if (relay.service(serviceName) != null) {
              someUnavailable = true;
              continue;
            }

            services.push({ service: serviceName, type: serviceType });
          }

          if (someInvalidService) {
            options.log.trace(
              `received bind request, some service types are not valid`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.SERVICE_INVALID_TYPE,
              ]),
            );
            if (isBlockingFailure("bind-invalid-service-type")) return;
            else break;
          }
          if (someUnauthorized) {
            options.log.trace(
              `received bind request, but some services are unauthorized`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("bind-unauthorized-services")) return;
            else break;
          }
          if (someUnavailable) {
            options.log.trace(
              `received bind request, but some services are already bound`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.SERVICE_ALREADY_BOUND,
              ]),
            );
            if (isBlockingFailure("bind-already-bound-services")) return;
            else break;
          }

          options.log.trace(`received bind request, services bound`, services);
          writer.write(
            new Uint8Array([RelayCommand.SERVICE_BIND, RelayBindReply.SUCCESS]),
          );
          relay.bind(socket, services);

          break;
        }

        case RelayCommand.SERVICE_CONNECT: {
          const encodedUID = buffer.data(4, { ahead: true });
          const uid = buffer.int32();

          if (!security.permissions.connect.enabled) {
            options.log.trace(
              `received connect request, but connect is not allowed`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("connect-unauthorized")) return;
            else break;
          }

          if (uid <= 0 || relay.connection(socket, uid)) {
            options.log.trace(`received connect request, but uid is not valid`);
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_INVALID_IDENTIFIER,
              ]),
            );
            if (isBlockingFailure("connect-invalid-uid")) return;
            else break;
          }

          const serviceType = buffer.uint8();

          if (!(serviceType in RelayServiceType)) {
            options.log.trace(
              `received connect request, but service type is not valid`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_INVALID_TYPE,
              ]),
            );
            if (isBlockingFailure("connect-invalid-service-type")) return;
            else break;
          }

          const service = buffer.data(buffer.uint16());

          const serviceName = decoder.decode(service);

          const allowed = await security.permissions.connect.allowed(
            serviceName,
          );
          if (!allowed) {
            options.log.trace(
              `received connect request, but service is not authorized`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("connect-unauthorized-service")) return;
            else break;
          }

          const found = relay.service(serviceName);
          if (found == null) {
            options.log.trace(
              `received connect request, but service is not found '${serviceName}'`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_NOT_FOUND,
              ]),
            );
            if (isBlockingFailure("connect-service-not-found")) return;
            else break;
          }

          if (found !== serviceType) {
            options.log.trace(
              `received connect request, but service type does not match`,
            );
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_INVALID_TYPE,
              ]),
            );
            if (isBlockingFailure("connect-non-matching-service-type")) return;
            else break;
          }

          options.log.trace(`received connect request, linked`);
          relay.link(socket, serviceName, uid, buffer.dataLeft());

          break;
        }

        case RelayCommand.SERVICE_LINK: {
          const encodedUID = buffer.data(4, { ahead: true });
          const uid = buffer.int32();
          const reply = buffer.uint8();

          const connection = relay.connection(socket, uid);
          if (!connection) {
            if (reply === RelayLinkReply.SUCCESS) {
              writer.write(
                new Uint8Array([
                  RelayCommand.SERVICE_CLOSED,
                  ...encodedUID,
                  RelayServiceConnectionReason.CONNECTION_GONE,
                ]),
              );
            }
          } else {
            connection.notify(socket, reply);
          }

          break;
        }

        case RelayCommand.SERVICE_STREAM: {
          const encodedUID = buffer.data(4, { ahead: true });
          const uid = buffer.int32();

          const connection = relay.connection(socket, uid);
          if (!connection) {
            writer.write(
              new Uint8Array([
                RelayCommand.SERVICE_CLOSED,
                ...encodedUID,
                RelayServiceConnectionReason.CONNECTION_GONE,
              ]),
            );
          } else {
            connection.forward(socket, buffer.dataLeft());
          }
          break;
        }

        case RelayCommand.SERVICE_CLOSED: {
          const uid = buffer.int32();
          const reason = buffer.uint8();

          relay.connection(socket, uid)?.close(socket, reason);
          break;
        }

        case RelayCommand.UNSUPPORTED: {
          const unsupportedCommand = buffer.uint8();
          options.log.error(
            `client notified unsupported command: ${
              printEnum(
                RelayCommand,
                unsupportedCommand,
              )
            }`,
          );
          break;
        }

        default: {
          options.log.warn(
            `received unsupported command: ${printEnum(RelayCommand, command)}`,
          );
          writer.write(new Uint8Array([RelayCommand.UNSUPPORTED, command]));
          if (isBlockingFailure("unsupported-command")) return;
          else break;
        }
      }
    }
  } finally {
    socket.onopen = null;
    socket.onclose = null;
    socket.onerror = null;
    socket.onmessage = null;

    relay.disconnected(socket);

    safelyClose(socket);
  }
}

export function createRelay(log: Logger): Relay {
  type RegisteredSocket = {
    write: TunnelWriter;
    relayCounter: number;
    connections: Map<number, RelayServiceConnection>;
  };

  const boundServices = new Map<
    string,
    { socket: WebSocket; type: RelayServiceType }
  >();
  const registeredSockets = new Map<WebSocket, RegisteredSocket>();

  return {
    connected: (socket, write) => {
      registeredSockets.set(socket, {
        write,
        relayCounter: 0,
        connections: new Map(),
      });
    },
    disconnected: (socket: WebSocket) => {
      // TODO: Verify that this doesn't throw some sort of concurrent modification error,
      //       Otherwise clone the list of services to remove first
      boundServices
        .entries()
        .filter(([, { socket: s }]) => s === socket)
        .forEach(([service]) => boundServices.delete(service));

      // TODO: Verify that this doesn't throw some sort of concurrent modification error,
      //       Otherwise clone the list of activeConnections first
      registeredSockets
        .get(socket)
        ?.connections.values()
        .forEach((c) =>
          c.close(socket, RelayServiceConnectionReason.TRANSPORT_SOCKET_CLOSED)
        );

      registeredSockets.delete(socket);
    },

    service: (service: string) => {
      const found = boundServices.get(service);
      return found?.type;
    },
    bind: (socket: WebSocket, services: RelayService[]) => {
      if (services.some((s) => boundServices.has(s.service))) {
        throw new Error("Already bound");
      }

      services.forEach(({ service, type }) => {
        boundServices.set(service, { socket, type });
      });
    },

    connection: (socket, uid) => {
      return registeredSockets.get(socket)!.connections.get(uid);
    },
    link: (clientSocket, service, clientUid, metadata) => {
      const bound = boundServices.get(service);
      if (!bound) throw new Error("Service not found");

      const client = registeredSockets.get(clientSocket)!;
      const server = registeredSockets.get(bound.socket)!;

      const serverSocket = bound.socket;
      const serverUid = --server.relayCounter;

      const connection: RelayServiceConnection = {
        client: { socket: clientSocket, uid: clientUid, write: client.write },
        server: { socket: serverSocket, uid: serverUid, write: server.write },

        close: (source, reason) => {
          const target = source === serverSocket
            ? connection.client
            : connection.server;

          try {
            const closeBuffer = new Uint8Array(6);

            closeBuffer[0] = RelayCommand.SERVICE_CLOSED;
            new DataView(closeBuffer.buffer).setInt32(1, target.uid);
            closeBuffer[5] = reason;

            target.write(closeBuffer);
          } finally {
            client.connections.delete(clientUid);
            server.connections.delete(serverUid);
          }
        },
        forward: (source, data) => {
          const target = source === serverSocket
            ? connection.client
            : connection.server;

          const forwardBuffer = new Uint8Array(5 + data.length);

          forwardBuffer[0] = RelayCommand.SERVICE_STREAM;
          new DataView(forwardBuffer.buffer).setInt32(1, target.uid);
          forwardBuffer.set(data, 5);

          target.write(forwardBuffer);
        },
        notify: (source, reply) => {
          const target = source === serverSocket
            ? connection.client
            : connection.server;

          target.write(
            new Uint8Array([
              RelayCommand.SERVICE_CONNECT,
              ...encodeInt32(target.uid),
              reply,
            ]),
          );
        },
      };

      client.connections.set(clientUid, connection);
      server.connections.set(serverUid, connection);

      const linkBuffer = new Uint8Array([
        RelayCommand.SERVICE_LINK,
        ...encodeInt32(serverUid),
        ...encodeWithUint16Length(new TextEncoder().encode(service)),
        ...metadata,
      ]);

      server.write(linkBuffer);
    },
  };
}
