import { Logger, prefixLogger } from "../../../common/log.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
  safelyClose,
} from "../../../common/utils.ts";
import { SocksTunnelResponse } from "../../../proxy/socks.common.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { RelayServiceType } from "../../server/tunnel.relay.ts";

export type TunnelClientHandledRawSocketClient = {
  readonly type: RelayServiceType.RAW_SOCKET;
  readonly emit: (tunnel: SocksTunnelResponse) => void;
  readonly log: Logger;

  expired: boolean;
};

export type TunnelClientRawSocketSericeServer = {
  definition: TunnelRelayClientOptions["services"]["connect"][number];
  handle: ConsumableAsyncQueue<TunnelClientHandledRawSocketClient>;
  done: Promise<void>;
};

export function createTunnelClientRawSocketSericeServer(
  options: {
    connection: TunnelRelayClientOptions["services"]["connect"][number];
    handleTimeout: number;

    log: Logger;
    signal: AbortSignal;
  },
): TunnelClientRawSocketSericeServer {
  const handle = consumableAsyncQueue<TunnelClientHandledRawSocketClient>({
    signal: options.signal,
  });

  const done = (async () => {
    options.log.info("Starting server");
    const listener = Deno.listen(options.connection.source);

    const closeListener = () => listener.close();
    options.signal.addEventListener("abort", closeListener, { once: true });

    options.log.info("Listening for connections");
    try {
      for await (const connection of listener) {
        const uid = crypto.randomUUID();
        const connectionLog = prefixLogger(options.log, [
          `[connection:${uid}]`,
        ]);

        if (handle.aborted()) {
          connectionLog.info("got connection but already aborted, closing it");
          connection.close();
          continue;
        }

        connectionLog.debug("got connection");

        const { promise, resolve } = Promise.withResolvers<
          SocksTunnelResponse
        >();

        const client: TunnelClientHandledRawSocketClient = {
          type: RelayServiceType.RAW_SOCKET,
          emit: resolve,
          log: connectionLog,
          expired: false,
        };

        const handleTimeout = setTimeout(() => {
          connectionLog.debug(`connection expired`);

          client.expired = true;
          client.emit({ ok: false, error: "ttl-expired" });
        }, options.handleTimeout);

        handle.push(client, {
          onAborted: () => {
            clearTimeout(handleTimeout);

            client.expired = true;
            client.emit({ ok: false, error: "general-failure" });
          },
          onDequeue: () => {
            connectionLog.debug(`connection being handled`);
            clearTimeout(handleTimeout);
          },
        });

        promise.then((result) => {
          if (result.ok) {
            connectionLog.debug(`relay connection established, piping traffic`);

            Promise
              .all([
                result.tunnel.readable.pipeTo(connection.writable),
                connection.readable.pipeTo(result.tunnel.writable),
              ])
              .catch((err) => {
                if (err instanceof Deno.errors.Interrupted) return;

                connectionLog.debug(`error handling piped traffic`, err);
              })
              .finally(() => {
                safelyClose(connection);
                safelyClose(result.tunnel);
              });
          } else {
            connectionLog.debug(`relay connection failed '${result.error}'`);
            safelyClose(connection);
          }
        });
      }
    } finally {
      options.signal.removeEventListener("abort", closeListener);
    }
  })();

  return { definition: options.connection, handle, done };
}
