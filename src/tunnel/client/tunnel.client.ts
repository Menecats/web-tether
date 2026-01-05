import { delay } from "@std/async/delay";
import { prefixLogger } from "../../common/log.ts";
import { deriveSignal } from "../../common/utils.ts";
import { TunnelRelayClientOptions } from "../common/tunnel.common.types.ts";
import { TunnelClientError } from "../common/tunnel.errors.ts";
import { validateTunnelClientConfiguration } from "./config/validate.ts";
import { createTunnelClientRawSocketSericeServer } from "./services/raw-socket-server.service.ts";
import { createTunnelClientSocksProxyServiceServer } from "./services/socks-proxy-server.service.ts";
import { handleClientSocket } from "./tunnel-handle.client.ts";

export async function createTunnelRelayClient(
  options: TunnelRelayClientOptions,
) {
  options.log.debug("validate configuration");
  await validateTunnelClientConfiguration(options);

  if (options.services.proxyClient.enabled) {
    options.log.debug("create [socks-proxy] listeners");
  }
  const socksProxyListeners = options.services.proxyClient.enabled
    ? [
      createTunnelClientSocksProxyServiceServer({
        proxy: options.services.proxyClient,
        handleTimeout: options.performance.connectionHandleTimeout,
        log: prefixLogger(options.log, `[socks-proxy]`),
        signal: options.signal,
      }),
    ]
    : [];

  if (options.services.connect.length) {
    options.log.debug("create [raw-socket listeners");
  }
  const rawSocketListeners = options.services.connect.map((connection) =>
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
    let lastAbortReason: unknown | undefined = undefined;
    while (!options.signal.aborted) {
      if (failed) {
        const waitDelay = options.performance.reconnectDelay({
          attempts: failed,
          valid: connectedOnce,
          reason: lastAbortReason,
        });
        lastAbortReason = undefined;

        if (waitDelay === false) {
          options.log.info(
            `connection won't retry after #${failed} failed attempt(s)`,
          );
          break;
        }

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

      lastAbortReason = socketAbort.signal.reason;
    }
  } catch (err) {
    options.log.error("error while handling connection loop", err);
  }
  options.log.trace("connection loop done");
}
