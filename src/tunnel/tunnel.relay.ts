import { delay } from "@std/async";
import { consumableAsyncQueue, safelyClose } from "../common/utils.ts";
import { handleAdvencedAuthenticationMode } from "./auth/advanced-authentication.ts";
import { handleBasicAuthenticationMode } from "./auth/basic-authentication.ts";
import { RelayAuthentication, RelayVersion7 } from "./tunnel.const.ts";
import { TunnelSecurity } from "./tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "./tunnel.server.ts";

export type RelayRequest = { timeout: number };
export type RelayPacket = { buffer: Uint8Array<ArrayBuffer>; view: DataView };

export type RelayHandler = AsyncGenerator<
  RelayRequest,
  TunnelSecurity | undefined,
  RelayPacket
>;

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

async function* authenticateRelay(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
): RelayHandler {
  // Determine protocol version
  const packet = yield { timeout: 1000 }; // TODO: Define timeout
  if (packet.buffer[0] !== RelayVersion7) return;

  const authMode = packet.buffer[1];

  const authPacket = {
    buffer: packet.buffer.subarray(2),
    view: new DataView(
      packet.buffer.buffer,
      packet.buffer.byteOffset + 2,
      packet.buffer.byteLength - 2,
    ),
  } satisfies RelayPacket;

  if (authMode === RelayAuthentication.BASIC_AUTH) {
    if (options.auth.basic.enabled) {
      return yield* handleBasicAuthenticationMode(
        options,
        socket,
        authPacket,
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return;
    }
  }

  if (authMode === RelayAuthentication.ADVANCED_AUTH) {
    if (options.auth.advanced.enabled) {
      return yield* handleAdvencedAuthenticationMode(
        options,
        socket,
        authPacket,
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return;
    }
  }

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.UNSUPPORTED_AUTH,
    ]),
  );
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
    // Create received messages queue
    using queue = consumableAsyncQueue<ArrayBuffer>();

    socket.binaryType = "arraybuffer";
    socket.onmessage = ({ data }) => {
      if (!(data instanceof ArrayBuffer)) return queue[Symbol.dispose]();

      queue.push(data);
    };

    // Wait for socket to open
    const opened = Promise.withResolvers<void>();
    socket.onopen = () => queue.disposed() ? opened.reject() : opened.resolve();
    socket.onclose = () => opened.reject();
    socket.onerror = () => opened.reject();
    await opened.promise;

    // Track closure or errors
    socket.onopen = null;
    socket.onclose = () => queue[Symbol.dispose]();
    socket.onerror = () => queue[Symbol.dispose]();

    const relayHandler = authenticateRelay(options, socket);

    let request: RelayRequest | undefined;
    let security: TunnelSecurity | undefined;

    while (true) {
      if (options.signal.aborted) {
        await relayHandler.throw("interrupted"); // TODO
        return;
      }

      let buffer: ArrayBuffer;
      if (!request) {
        buffer = new ArrayBuffer(0);
      } else {
        try {
          buffer = await Promise.race([
            queue.shift(),
            delay(request.timeout, {
              persistent: false,
              signal: options.signal,
            }).catch(() => {
              throw "interrupted"; // TODO
            }).then(() => {
              throw "timed-out"; // TODO
            }),
          ]);
        } catch (err) {
          await relayHandler.throw(err);
          return;
        }
      }

      const result = await relayHandler.next({
        buffer: new Uint8Array(buffer),
        view: new DataView(buffer),
      });
      if (result.done) {
        request = undefined;
        security = result.value;
        break;
      }

      request = result.value;
    }

    // Security must be configured to proceed
    if (!security) return;

    using decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>(
      (packet, signal) => security.decrypt(packet, signal),
    );

    (async () => {
      try {
        while (true) {
          const encryptedPacket = await queue.shift();

          if (decryptQueue.queued() >= options.auth.queueSize) {
            await decryptQueue.waitFor("dequeue");
          }
          decryptQueue.push(encryptedPacket);
        }
      } finally {
        decryptQueue[Symbol.dispose]();
      }
    })();

    const decoder = new TextDecoder();
    let serviceBound = false;

    relay.connected(socket);

    while (true) {
      const buffer = new Uint8Array(await decryptQueue.shift());
      const view = new DataView(buffer.buffer);

      let offset = 0;
      const command = buffer[offset++];
      switch (command) {
        case RelayCommand.SOCKET_CLOSE: {
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

          const servicesCount = view.getUint16(offset);
          offset += 2;

          let someUnavailable = false;
          let someUnauthorized = false;
          let someInvalidService = false;

          const services: RelayService[] = [];

          for (let i = 0; i < servicesCount; ++i) {
            const serviceType = view.getUint8(offset);
            offset += 1;

            const serviceLength = view.getUint16(offset);
            offset += 2;

            const serviceName = decoder.decode(
              buffer.subarray(offset, offset + serviceLength),
            );
            offset += serviceLength;

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
          const uid = view.getInt32(offset);
          const encodedUID = buffer.subarray(offset, offset + 4);
          offset += 4;

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

          const serviceType = view.getUint8(offset);
          offset += 1;

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

          const serviceLength = view.getUint16(offset);
          offset += 2;

          const serviceName = decoder.decode(
            buffer.subarray(offset, offset + serviceLength),
          );
          offset += serviceLength;

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
          const uid = view.getInt32(offset);
          offset += 4;

          const connection = relay.connection(socket, uid);
          if (!connection) {
            const closeBuffer = new Uint8Array(6);

            closeBuffer[0] = RelayCommand.SERVICE_CLOSED;
            new DataView(closeBuffer.buffer).setInt32(1, uid);
            closeBuffer[5] = RelayServiceConnectionReason.CONNECTION_GONE;

            socket.send(closeBuffer);
          } else {
            connection.forward(socket, buffer.subarray(offset));
          }
          break;
        }

        case RelayCommand.SERVICE_CLOSED: {
          const uid = view.getInt32(offset);
          offset += 4;

          const reason = buffer[offset++];

          relay.connection(socket, uid)?.close(socket, reason);
          break;
        }

        default: {
          socket.send(new Uint8Array([RelayCommand.UNSUPPORTED]));
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
        .get(socket)!
        .connections
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
