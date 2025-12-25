import { delay } from "@std/async/delay";
import { prefixLogger } from "../common/log.ts";
import { deriveSignal } from "../common/utils.ts";
import { validateTunnelClientConfiguration } from "./client/config/validate.ts";
import {
  createTunnelClientRawSocketSericeServer,
} from "./client/services/raw-socket-server.service.ts";
import {
  createTunnelClientSocksProxyServiceServer,
} from "./client/services/socks-proxy-server.service.ts";
import { handleClientSocket } from "./client/tunnel-handle.client.ts";
import { TunnelRelayClientOptions } from "./common/tunnel.common.types.ts";
import { TunnelClientError } from "./tunnel.errors.ts";

export async function createTunnelRelayClient(
  options: TunnelRelayClientOptions,
) {
  options.log.debug("validate configuration");
  await validateTunnelClientConfiguration(options);

  if (options.services.proxyClient.length) {
    options.log.debug("create [socks-proxy] listeners");
  }
  const socksProxyListeners = options.services.proxyClient
    .map((proxy) =>
      createTunnelClientSocksProxyServiceServer({
        proxy,
        handleTimeout: options.performance.connectionHandleTimeout,
        log: prefixLogger(options.log, `[socks-proxy:${proxy.service}]`),
        signal: options.signal,
      })
    );

  if (options.services.connect.length) {
    options.log.debug("create [raw-socket listeners");
  }
  const rawSocketListeners = options.services.connect
    .map((connection) =>
      createTunnelClientRawSocketSericeServer({
        connection,
        handleTimeout: options.performance.connectionHandleTimeout,
        log: prefixLogger(options.log, `[raw-socket:${connection.service}]`),
        signal: options.signal,
      })
    );

  let connectedOnce = false;
  let failed = 0;

  options.log.trace("starting loop done");
  try {
    while (!options.signal.aborted) {
      if (failed) {
        const waitDelay = options.performance.reconnectDelay({
          attempts: failed,
          valid: connectedOnce,
        });

        options.log.info(
          `delay connection after #${failed} failed attempt(s), waiting ${waitDelay}ms`,
        );

        await delay(waitDelay, { signal: options.signal });
      }

      options.log.debug(`connecting to '${options.endpoint}'`);

      const log = prefixLogger(options.log, "[socket]");

      const socket = new WebSocket(options.endpoint);
      socket.binaryType = "arraybuffer";

      const socketAbort = deriveSignal(options.signal);
      socketAbort.signal.addEventListener("abort", () => socket.close(), {
        once: true,
      });

      try {
        await handleClientSocket({
          socket,
          options,
          signal: socketAbort.signal,
          log,

          connected: () => {
            connectedOnce = true;
            failed = 0;
          },

          services: {
            socksProxies: socksProxyListeners,
            rawSockets: rawSocketListeners,
          },
        });
      } catch (error) {
        log.error("error handling socket", error);
        failed++;

        socketAbort.abort(error);
      } finally {
        // This abort is emitted only if not already performed in the 'catch'
        log.trace("done handling socket");
        socketAbort.abort(new TunnelClientError({ reason: "socket-closed" }));
      }
    }
  } catch (err) {
    options.log.error("error while handling connection loop", err);
  }
  options.log.trace("connection loop done");
}
