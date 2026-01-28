import { asyncAction } from "../../../common/async.ts";
import { createConnectionTunnelPair } from "../../../common/communication.ts";
import { Logger, prefixLogger } from "../../../common/log.ts";
import {
  encodeInt32,
  encodeUint16,
  encodeWithUint16Length,
} from "../../../common/safe-buffer.ts";
import {
  cancellableAbort,
  consumableAsyncQueue,
  safelyClose,
} from "../../../common/utils.ts";
import { TunnelWriter } from "../../common/tunnel.common.types.ts";
import { errorLevel } from "../../common/tunnel.errors.ts";
import { RelayCommand, RelayServiceType } from "../../server/tunnel.relay.ts";
import { TunnelClientConnection } from "../tunnel.client.types.ts";
import { handleClientStream } from "./handle-stream.ts";
import { TunnelClientRawSocketSericeServer } from "./raw-socket-server.service.ts";
import { TunnelClientSocksProxyServiceServer } from "./socks-proxy-server.service.ts";

export async function handleTunnelClientServices({
  services,
  generateUID,

  connections,

  write,
  signal,
  encoder,
  log,
}: {
  services: (
    | TunnelClientRawSocketSericeServer
    | TunnelClientSocksProxyServiceServer
  )[];
  generateUID: () => number;

  connections: Map<number, TunnelClientConnection>;

  write: TunnelWriter;
  signal: AbortSignal;
  encoder: TextEncoder;
  log: Logger;
}) {
  await Promise.all(
    services.map((service) => {
      const serviceLog = prefixLogger(
        log,
        `[${
          "service" in service.definition
            ? service.definition.service
            : "@proxy"
        }]`,
      );

      return asyncAction(
        async ({ signal: actionSignal }) => {
          try {
            while (!actionSignal.aborted) {
              serviceLog.trace("waiting for client");

              const client = await service.handle.shift({
                signal: actionSignal,
              });
              if (client.expired || actionSignal.aborted) continue;

              const uid = generateUID();
              const encodedUID = encodeInt32(uid);

              const requestLog = prefixLogger(serviceLog, `[${uid}]`);

              requestLog.trace(`client received, creating connections pair`);
              const [relayTunnel, serviceTunnel] = createConnectionTunnelPair();

              const { promise: done, resolve: finalize } = Promise
                .withResolvers<void>();

              const outputQueue = consumableAsyncQueue<Uint8Array<ArrayBuffer>>(
                {
                  signal: actionSignal,
                },
              );

              const onAbort = cancellableAbort(actionSignal, (reason) => {
                requestLog.trace(`remote connection cancelled`, reason);
                client.emit({ ok: false, error: "general-failure" });

                finalize();
              });

              let connected = false;
              connections.set(uid, {
                uid,
                tunnel: relayTunnel,

                onConnect: () => {
                  connected = true;

                  requestLog.trace(`remote client connected`);
                  client.emit({ ok: true, tunnel: serviceTunnel });

                  handleClientStream({
                    uid,
                    write,
                    tunnel: relayTunnel,
                    signal: actionSignal,
                    log: requestLog,
                    outputQueue,
                  }).finally(finalize);
                },
                onError: (reason) => {
                  requestLog.trace(
                    `remote connection failed due to '${reason}'`,
                  );
                  client.emit({ ok: false, error: reason });

                  finalize();
                },

                write: (content) => outputQueue.push(content),
                close: () => {
                  requestLog.trace(`closing connection`);
                  finalize();
                },
                done,
              });
              done.finally(() => {
                connections.delete(uid);
                safelyClose(relayTunnel);
                onAbort.cancel();
                if (!connected) {
                  client.emit({ ok: false, error: "general-failure" });
                }
              });

              requestLog.trace(`send connect request to relay`);

              const serviceParameters =
                client.type === RelayServiceType.SOCKS_PROXY
                  ? [
                    ...encodeWithUint16Length(
                      encoder.encode(client.destination.host),
                    ),
                    ...encodeUint16(client.destination.port),
                  ]
                  : [];

              write(
                new Uint8Array([
                  RelayCommand.SERVICE_CONNECT,
                  ...encodedUID,
                  client.type,
                  ...encodeWithUint16Length(encoder.encode(client.service)),
                  ...serviceParameters,
                ]),
              );
            }
          } catch (err) {
            serviceLog[errorLevel(err)]("error while listening service", err);
          }
        },
        { signal },
      ).done;
    }),
  );
}
