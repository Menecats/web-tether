import { Logger } from "../../../common/log.ts";
import {
  ConsumableAsyncQueue,
  consumableAsyncQueue,
} from "../../../common/utils.ts";
import {
  SocksDestinationAddress,
  SocksTunnelResponse,
} from "../../../proxy/socks.common.ts";
import { createSocksServer } from "../../../proxy/socks.server.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { RelayServiceType } from "../../tunnel.relay.ts";

export type TunnelClientHandledSocksProxyClient = {
  readonly type: RelayServiceType.SOCKS_PROXY;
  readonly emit: (tunnel: SocksTunnelResponse) => void;
  readonly destination: SocksDestinationAddress;
  readonly log: Logger;

  expired: boolean;
};

export type TunnelClientSocksProxyServiceServer = {
  definition: TunnelRelayClientOptions["services"]["proxyClient"][number];
  handle: ConsumableAsyncQueue<TunnelClientHandledSocksProxyClient>;
  done: Promise<void>;
};

export function createTunnelClientSocksProxyServiceServer(
  options: {
    proxy: TunnelRelayClientOptions["services"]["proxyClient"][number];
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
    tunnel: async (destination, log) => {
      if (handle.aborted()) throw handle.abortReason();

      const result = Promise.withResolvers<SocksTunnelResponse>();

      const client: TunnelClientHandledSocksProxyClient = {
        type: RelayServiceType.SOCKS_PROXY,
        emit: result.resolve,
        destination,
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
