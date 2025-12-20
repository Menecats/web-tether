import { Logger, prefixLogger } from "../common/log.ts";
import { encodeUint32, safeReader } from "../common/safe-buffer.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
  safelyClose,
} from "../common/utils.ts";
import { handleAdvencedAuthenticationServer } from "./auth/server/advanced-authentication.server.ts";
import { handleBasicAuthenticationServer } from "./auth/server/basic-authentication.server.ts";
import { RelayAuthentication, RelayVersion7 } from "./tunnel.const.ts";
import { TunnelServerError } from "./tunnel.errors.ts";
import { TunnelSecurity } from "./tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "./tunnel.server.ts";

export enum RelayBindReply {
  SUCCESS = 0x01,
  SOCKET_ALREADY_BOUND = 0x30,
  SERVICE_ALREADY_BOUND = 0x31,
  SERVICE_INVALID_TYPE = 0x32,
  UNAUTHORIZED = 0xFE,
}
export enum RelayConnectReply {
  SERVICE_INVALID_TYPE = 0x32,
  SERVICE_NOT_FOUND = 0x33,
  INVALID_IDENTIFIER = 0x34,
  UNAUTHORIZED = 0xFE,
}

export enum RelayCommand {
  SOCKET_CLOSE = 0x00,

  SERVICE_BIND = 0x10,
  SERVICE_CONNECT = 0x11,
  SERVICE_STREAM = 0x12,
  SERVICE_LINK = 0x13,
  SERVICE_CLOSED = 0x14,

  UNSUPPORTED = 0xFF,
}

export enum RelayServiceType {
  RAW_SOCKET = 0x00,
  SOCKS_PROXY = 0x01,
}

export type RelayService = {
  type: RelayServiceType;
  service: string;
};

export type RelayServiceConnectionStatus = "requested";
export enum RelayServiceConnectionReason {
  TRANSPORT_SOCKET_EOS = 0x00,
  TRANSPORT_SOCKET_CLOSED = 0x01,
  TRANSPORT_FORWARD_FAILED = 0x02,
  TRANSPORT_SOCKET_START_FAILED = 0x03,
  CONNECTION_GONE = 0xFE,
  UNKNOWN = 0xFF,
}
export type RelayServiceConnection = {
  status: RelayServiceConnectionStatus;

  readonly server: { socket: WebSocket; uid: number };
  readonly client: { socket: WebSocket; uid: number };

  close(source: WebSocket, reason: RelayServiceConnectionReason): void;
  forward(source: WebSocket, buffer: Uint8Array): void;
};

export type Relay = {
  service: (service: string) => RelayServiceType | undefined;
  bind: (socket: WebSocket, services: RelayService[]) => void;

  connection: (
    socket: WebSocket,
    uid: number,
  ) => RelayServiceConnection | undefined;
  link: (socket: WebSocket, service: string, uid: number) => void;

  connected: (socket: WebSocket) => void;
  disconnected: (socket: WebSocket) => void;
};

async function authenticateRelay(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayOptions["auth"],
  log: Logger,
): Promise<TunnelSecurity<"relay"> | undefined> {
  log.debug(`waiting handshake`);
  const packet = safeReader(
    await queue.shift({
      timeout: 1000,
      timeoutError: () => new TunnelServerError({ reason: "timeout" }),
    }),
    () => new TunnelServerError({ reason: "buffer-too-short" }),
  );

  const version = packet.uint8();
  if (version !== RelayVersion7) {
    throw new TunnelServerError({ reason: "unknown-version", version });
  }

  const authMode = packet.uint8();

  if (authMode === RelayAuthentication.BASIC_AUTH) {
    if (auth.basic.enabled) {
      return await handleBasicAuthenticationServer(
        socket,
        queue,
        auth.basic,
        packet,
        prefixLogger(log, "[basic]"),
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return undefined;
    }
  }

  if (authMode === RelayAuthentication.ADVANCED_AUTH) {
    if (auth.advanced.enabled) {
      return await handleAdvencedAuthenticationServer(
        socket,
        queue,
        auth.advanced,
        packet,
        prefixLogger(log, "[advanced]"),
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return undefined;
    }
  }

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.UNSUPPORTED_AUTH,
    ]),
  );
  return undefined;
}

// TODO:
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
    using queue = consumableAsyncQueue<ArrayBuffer>({
      signal: options.signal,
    });
    const ready = Promise.withResolvers<void>();

    options.log.trace(`setting up socket content and listeners`);

    socket.binaryType = "arraybuffer";
    socket.onmessage = ({ data }) => {
      if (data instanceof ArrayBuffer) queue.push(data);
    };
    socket.onopen = () =>
      queue.aborted() ? ready.reject(queue.abortReason()) : ready.resolve();
    socket.onclose = () =>
      ready.reject(new TunnelServerError({ reason: "socket-closed" }));
    socket.onerror = (event) =>
      ready.reject(
        new TunnelServerError({
          reason: "socket-error",
          error: ("error" in event) ? event.error : event,
        }),
      );

    options.log.trace(`waiting for socket to connect`);
    await ready.promise;
    options.log.debug(`connected`);

    options.log.trace(`updating socket listeners`);
    socket.onopen = null;
    socket.onclose = () =>
      queue.abortWith(new TunnelServerError({ reason: "socket-closed" }));
    socket.onerror = (event) =>
      queue.abortWith(
        new TunnelServerError({
          reason: "socket-error",
          error: ("error" in event) ? event.error : event,
        }),
      );

    options.log.trace(`authenticate socket`);
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

    options.log.trace(`setting up decrypted queue`);
    using decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>({
      signal: options.signal,
      map: (packet, signal) => security.decrypt(packet, signal),
    });

    (async () => {
      try {
        while (true) {
          const encryptedPacket = await queue.shift();
          if (decryptQueue.queued() >= options.performance.decryptQueueSize) {
            await decryptQueue.waitFor("dequeue");
          }
          decryptQueue.push(encryptedPacket);
        }
      } catch (error) {
        if (!queue.aborted()) {
          queue.abortWith(
            (error instanceof TunnelServerError)
              ? error
              : new TunnelServerError({ reason: "unknown-error", error }),
          );
        }

        decryptQueue.abortWith(queue.abortReason());
      }
    })();

    const decoder = new TextDecoder();
    let serviceBound = false;

    relay.connected(socket);

    options.log.trace(`ready, waiting commands`);
    while (!options.signal.aborted) {
      const buffer = safeReader(
        await decryptQueue.shift(),
        () => new TunnelServerError({ reason: "buffer-too-short" }),
      );

      const command = buffer.uint8();

      switch (command) {
        case RelayCommand.SOCKET_CLOSE: {
          options.log.debug(`received close command`);
          socket.send(new Uint8Array([RelayCommand.SOCKET_CLOSE]));
          return;
        }

        case RelayCommand.SERVICE_BIND: {
          if (!security.permissions.bind.enabled) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("bind-unauthorized")) return;
            else break;
          }

          if (serviceBound) {
            socket.send(
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

            if (relay.service(serviceName)) {
              someUnavailable = true;
              continue;
            }

            services.push({ service: serviceName, type: serviceType });
          }

          if (someInvalidService) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.SERVICE_INVALID_TYPE,
              ]),
            );
            if (isBlockingFailure("bind-invalid-service-type")) return;
            else break;
          }
          if (someUnauthorized) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("bind-unauthorized-services")) return;
            else break;
          }
          if (someUnavailable) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_BIND,
                RelayBindReply.SERVICE_ALREADY_BOUND,
              ]),
            );
            if (isBlockingFailure("bind-already-bound-services")) return;
            else break;
          }

          socket.send(
            new Uint8Array([RelayCommand.SERVICE_BIND, RelayBindReply.SUCCESS]),
          );
          relay.bind(socket, services);

          break;
        }

        case RelayCommand.SERVICE_CONNECT: {
          const uid = buffer.uint32();
          const encodedUID = encodeUint32(uid);

          if (!security.permissions.connect.enabled) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("connect-unauthorized")) return;
            else break;
          }

          if (uid <= 0 || relay.connection(socket, uid)) {
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.INVALID_IDENTIFIER,
              ]),
            );
            if (isBlockingFailure("connect-invalid-uid")) return;
            else break;
          }

          const serviceType = buffer.uint8();

          if (!(serviceType in RelayServiceType)) {
            socket.send(
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
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.UNAUTHORIZED,
              ]),
            );
            if (isBlockingFailure("connect-unauthorized-service")) return;
            else break;
          }

          const found = relay.service(serviceName);
          if (!found) {
            socket.send(
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
            socket.send(
              new Uint8Array([
                RelayCommand.SERVICE_CONNECT,
                ...encodedUID,
                RelayConnectReply.SERVICE_INVALID_TYPE,
              ]),
            );
            if (isBlockingFailure("connect-non-matching-service-type")) return;
            else break;
          }

          relay.link(socket, serviceName, uid);

          break;
        }

        case RelayCommand.SERVICE_STREAM: {
          const uid = buffer.uint32();

          const connection = relay.connection(socket, uid);
          if (!connection) {
            const closeBuffer = new Uint8Array(6);

            closeBuffer[0] = RelayCommand.SERVICE_CLOSED;
            new DataView(closeBuffer.buffer).setInt32(1, uid);
            closeBuffer[5] = RelayServiceConnectionReason.CONNECTION_GONE;

            socket.send(closeBuffer);
          } else {
            connection.forward(socket, buffer.dataLeft());
          }
          break;
        }

        case RelayCommand.SERVICE_CLOSED: {
          const uid = buffer.uint32();
          const reason = buffer.uint8();

          relay.connection(socket, uid)?.close(socket, reason);
          break;
        }

        default: {
          socket.send(new Uint8Array([RelayCommand.UNSUPPORTED, command]));
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

export function createRelay(): Relay {
  type RegisteredSocket = {
    relayCounter: number;
    connections: Map<number, RelayServiceConnection>;
  };

  const boundServices = new Map<
    string,
    { socket: WebSocket; type: RelayServiceType }
  >();
  const registeredSockets = new Map<WebSocket, RegisteredSocket>();

  return {
    connected: (socket: WebSocket) => {
      registeredSockets.set(socket, {
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
        ?.connections
        .values()
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

    connection: (
      socket: WebSocket,
      uid: number,
    ) => {
      return registeredSockets.get(socket)!.connections.get(uid);
    },
    link: (clientSocket: WebSocket, service: string, clientUid: number) => {
      const bound = boundServices.get(service);
      if (!bound) throw new Error("Service not found");

      const client = registeredSockets.get(clientSocket)!;
      const server = registeredSockets.get(bound.socket)!;

      const serverSocket = bound.socket;
      const serverUid = --server.relayCounter;

      const connection: RelayServiceConnection = {
        status: "requested",

        client: { socket: clientSocket, uid: clientUid },
        server: { socket: serverSocket, uid: serverUid },

        close: (source, reason) => {
          const target = source === serverSocket
            ? connection.client
            : connection.server;

          try {
            const closeBuffer = new Uint8Array(6);

            closeBuffer[0] = RelayCommand.SERVICE_CLOSED;
            new DataView(closeBuffer.buffer).setInt32(1, target.uid);
            closeBuffer[5] = reason;

            target.socket.send(closeBuffer);
          } catch (err) {
            // TODO: Log
          } finally {
            client.connections.delete(clientUid);
            server.connections.delete(serverUid);
          }
        },
        forward: (source, data) => {
          const target = source === serverSocket
            ? connection.client
            : connection.server;

          try {
            const forwardBuffer = new Uint8Array(5 + data.length);

            forwardBuffer[0] = RelayCommand.SERVICE_STREAM;
            new DataView(forwardBuffer.buffer).setInt32(1, target.uid);
            forwardBuffer.set(data, 5);

            target.socket.send(forwardBuffer);
          } catch (err) {
            // TODO: Log

            connection.close(
              target.socket,
              RelayServiceConnectionReason.TRANSPORT_FORWARD_FAILED,
            );
          }
        },
      };

      client.connections.set(clientUid, connection);
      server.connections.set(serverUid, connection);

      try {
        const linkBuffer = new Uint8Array(8);
        linkBuffer[0] = RelayCommand.SERVICE_LINK;
        new DataView(linkBuffer.buffer).setInt32(1, serverUid);

        serverSocket.send(linkBuffer);
      } catch (err) {
        // TODO: Log

        connection.close(
          serverSocket,
          RelayServiceConnectionReason.TRANSPORT_SOCKET_START_FAILED,
        );
      }
    },
  };
}
