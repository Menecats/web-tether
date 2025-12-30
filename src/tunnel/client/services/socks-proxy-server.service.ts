import { ConnectionTunnelErrorReason } from "../../../common/communication.ts";
import { Logger } from "../../../common/log.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
} from "../../../common/utils.ts";
import { SocksTunnelResponse } from "../../../proxy/socks.common.ts";
import { createSocksServer } from "../../../proxy/socks.server.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { RelayServiceType } from "../../server/tunnel.relay.ts";

export type TunnelClientHandledSocksProxyClient = {
  readonly type: RelayServiceType.SOCKS_PROXY;
  readonly service: string;
  readonly emit: (tunnel: SocksTunnelResponse) => void;
  readonly destination: { host: string; port: number };
  readonly log: Logger;

  expired: boolean;
};

export type TunnelClientSocksProxyServiceServer = {
  definition: TunnelRelayClientOptions["services"]["proxyClient"] & {
    enabled: true;
  };
  handle: ConsumableAsyncQueue<TunnelClientHandledSocksProxyClient>;
  done: Promise<void>;
};

export function createTunnelClientSocksProxyServiceServer(
  options: {
    proxy: TunnelRelayClientOptions["services"]["proxyClient"] & {
      enabled: true;
    };
    handleTimeout: number;

    log: Logger;
    signal: AbortSignal;
  },
): TunnelClientSocksProxyServiceServer {
  const handle = consumableAsyncQueue<TunnelClientHandledSocksProxyClient>({
    signal: options.signal,
  });

  const server = createSocksServer({
    listen: options.proxy.address,
    signal: options.signal,
    socks4: { enabled: true, auth: { enabled: false } },
    socks5: { enabled: true, auth: { enabled: false } },
    log: options.log,
    tunnel: async (request, log) => {
      if (handle.aborted()) throw handle.abortReason();

      log.trace("determining appropriate destination");
      const destination = await options.proxy.destination(request);
      if (destination.type === "abort") {
        log.trace("request explicitely aborted");
        return { ok: false, error: "not-allowed" };
      }

      if (destination.type === "local") {
        log.trace("request redirected locally");
        try {
          const tunnel = await Deno.connect({
            hostname: destination.destination.host,
            port: destination.destination.port,
          });

          log.trace(
            `connected to '${tunnel.remoteAddr.hostname}:${tunnel.remoteAddr.port}' from '${tunnel.localAddr.hostname}:${tunnel.localAddr.port}'.`,
          );

          return { ok: true, tunnel };
        } catch (err) {
          log.trace(
            `error connecting to '${destination.destination.host}:${destination.destination.port}'.`,
            err,
          );

          let error: ConnectionTunnelErrorReason;
          if (err instanceof Deno.errors.ConnectionRefused) {
            error = "connection-refused";
          } else if (err instanceof Deno.errors.NetworkUnreachable) {
            error = "network-unreachable";
          } else {
            error = "general-failure";
          }
          return { ok: false, error };
        }
      }

      log.trace(`relaying request to service '${destination.service}'`);

      const result = Promise.withResolvers<SocksTunnelResponse>();

      const client: TunnelClientHandledSocksProxyClient = {
        type: RelayServiceType.SOCKS_PROXY,
        service: destination.service,
        emit: result.resolve,
        destination: destination.destination,
        log,
        expired: false,
      };

      const handleTimeout = setTimeout(() => {
        log.debug(`tunnel expired`);

        client.expired = true;
        client.emit({ ok: false, error: "ttl-expired" });
      }, options.handleTimeout);

      handle.push(client, {
        onAborted: () => {
          clearTimeout(handleTimeout);

          client.expired = true;
          client.emit({ ok: false, error: "general-failure" });
        },
        onDequeue: () => clearTimeout(handleTimeout),
      });

      return await result.promise;
    },
  });

  return {
    definition: options.proxy,
    handle,
    done: server,
  };
}
