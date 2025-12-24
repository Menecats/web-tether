import {
  createCipheredWriter,
  createDecipheredQueue,
} from "../../common/communication.ts";
import { Logger } from "../../common/log.ts";
import {
  encodeUint16,
  encodeWithUint16Length,
  safeReader,
} from "../../common/safe-buffer.ts";
import { consumableAsyncQueue } from "../../common/utils.ts";
import { TunnelRelayClientOptions } from "../common/tunnel.common.types.ts";
import { TunnelClientError } from "../tunnel.errors.ts";
import { RelayCommand, RelayServiceType } from "../tunnel.relay.ts";
import { handleClientAuthentication } from "./auth/authentication.client.ts";
import { fallbackCommandHandler } from "./commands/fallback-command-handler.ts";
import { handle_SERVICE_BIND } from "./commands/handle-SERVICE_BIND.ts";
import { handle_SERVICE_CLOSED } from "./commands/handle-SERVICE_CLOSED.ts";
import { handle_SERVICE_CONNECT } from "./commands/handle-SERVICE_CONNECT.ts";
import { handle_SERVICE_LINK } from "./commands/handle-SERVICE_LINK.ts";
import { handle_SERVICE_STREAM } from "./commands/handle-SERVICE_STREAM.ts";
import { handle_SOCKET_CLOSED } from "./commands/handle-SOCKET_CLOSED.ts";
import { handle_UNSUPPORTED } from "./commands/handle-UNSUPPORTED.ts";
import {
  handleTunnelClientService as handleTunnelClientServices,
} from "./services/client-service-handler.ts";
import {
  TunnelClientRawSocketSericeServer,
} from "./services/raw-socket-server.service.ts";
import { TunnelClientSocksProxyServiceServer } from "./services/socks-proxy-server.service.ts";
import {
  TunnelClientCommandHandler,
  TunnelClientConnection,
  TunnelClientLink,
} from "./tunnel.client.types.ts";

const commandHandlers: Record<RelayCommand, TunnelClientCommandHandler> = {
  [RelayCommand.SOCKET_CLOSE]: handle_SOCKET_CLOSED,

  [RelayCommand.SERVICE_BIND]: handle_SERVICE_BIND,
  [RelayCommand.SERVICE_CONNECT]: handle_SERVICE_CONNECT,
  [RelayCommand.SERVICE_LINK]: handle_SERVICE_LINK,
  [RelayCommand.SERVICE_STREAM]: handle_SERVICE_STREAM,
  [RelayCommand.SERVICE_CLOSED]: handle_SERVICE_CLOSED,

  [RelayCommand.UNSUPPORTED]: handle_UNSUPPORTED,
};

export type HandleClientSocketOptions = {
  socket: WebSocket;
  options: Omit<TunnelRelayClientOptions, "log" | "signal">;
  signal: AbortSignal;
  log: Logger;

  connected: () => void;

  services: {
    socksProxies: TunnelClientSocksProxyServiceServer[];
    rawSockets: TunnelClientRawSocketSericeServer[];
  };
};
export async function handleClientSocket({
  socket,
  options,
  signal: socketSignal,
  log,
  connected: notifyConnected,
  services,
}: HandleClientSocketOptions) {
  log.trace(`configuring 'message' listener`);
  using queue = consumableAsyncQueue<ArrayBuffer>({ signal: socketSignal });
  socket.onmessage = ({ data }) => {
    if (data instanceof ArrayBuffer) queue.push(data);
  };

  log.trace(`configuring 'ready' listeners`);
  const ready = Promise.withResolvers<void>();
  socket.onopen = () => {
    if (queue.aborted()) {
      log.trace(
        "[listener] socket connection opened, but queue is already aborted, rejecting",
        queue.abortReason(),
      );
      ready.reject(queue.abortReason());
    } else {
      log.trace(
        "[listener] socket connection opened, notifying ready",
      );
      ready.resolve();
    }
  };
  socket.onclose = () => {
    log.trace(
      "[listener] socket connection closed before being opened, rejecting",
    );
    ready.reject(new TunnelClientError({ reason: "socket-closed" }));
  };
  socket.onerror = (event) => {
    log.trace(
      "[listener] socket connection errored before being opened, rejecting",
    );
    ready.reject(
      new TunnelClientError({
        reason: "socket-error",
        error: ("error" in event) ? event.error : event,
      }),
    );
  };
  log.trace(`waiting for socket to connect`);
  await ready.promise;

  log.trace(`configuring 'abort' listeners`);
  socket.onopen = null;
  socket.onclose = () => {
    log.trace(`[listener] connection closed, aborting queue`);
    queue.abortWith(new TunnelClientError({ reason: "socket-closed" }));
  };
  socket.onerror = (event) => {
    log.trace(`[listener] connection errored, aborting queue`);
    queue.abortWith(
      new TunnelClientError({
        reason: "socket-error",
        error: ("error" in event) ? event.error : event,
      }),
    );
  };

  log.trace(`perform handshake`);
  const security = await handleClientAuthentication({
    socket,
    queue,
    auth: options.auth,
    log,
  });

  notifyConnected();

  log.trace(`configure cipher writer and decrypted queue`);
  const writer = createCipheredWriter({
    socket,
    security,
    signal: socketSignal,
    log,
  });
  using decryptQueue = createDecipheredQueue({
    cipheredQueue: queue,
    security,
    signal: socketSignal,
    decryptQueueSize: options.performance.decryptQueueSize,
  });

  let localUID = 1;

  const registeredServices = new Map<
    string,
    | {
      type: RelayServiceType.SOCKS_PROXY;
      service: string;
    }
    | {
      type: RelayServiceType.RAW_SOCKET;
      service: string;
      destination: Omit<Deno.ConnectOptions, "signal">;
    }
  >();

  if (options.services.proxyServer.enabled) {
    registeredServices.set(options.services.proxyServer.service, {
      type: RelayServiceType.SOCKS_PROXY,
      service: options.services.proxyServer.service,
    });
  }
  options.services.bind.forEach((bind) => {
    registeredServices.set(bind.service, {
      type: RelayServiceType.RAW_SOCKET,
      service: bind.service,
      destination: bind.destination,
    });
  });

  const serviceConnections = new Map<number, TunnelClientConnection>();
  const serviceLinks = new Map<number, TunnelClientLink>();

  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  handleTunnelClientServices({
    services: [
      ...services.rawSockets,
      ...services.socksProxies,
    ],
    generateUID: () => localUID++,

    connections: serviceConnections,

    write: writer.write,
    signal: socketSignal,

    encoder,
    log,
  });

  if (registeredServices.size) {
    log.trace(`sending bind request`);
    writer.write(
      new Uint8Array([
        RelayCommand.SERVICE_BIND,
        ...encodeUint16(registeredServices.size),
        ...[...registeredServices.values()].flatMap((service) => [
          service.type,
          ...encodeWithUint16Length(encoder.encode(service.service)),
        ]),
      ]),
    );
  }

  log.trace(`waiting commands`);
  while (!socketSignal.aborted) {
    const buffer = safeReader(
      await decryptQueue.shift(),
      () => new TunnelClientError({ reason: "buffer-too-short" }),
    );

    const command = buffer.uint8();
    const commandHandler = commandHandlers[command as RelayCommand] ||
      fallbackCommandHandler;

    const result = await commandHandler({
      decoder,
      encoder,

      command,

      buffer,
      write: writer.write,
      log,

      signal: socketSignal,

      services: {
        registered: registeredServices,

        links: serviceLinks,
        connections: serviceConnections,
      },
    });
    if (result === "close-socket") break;
  }
}
