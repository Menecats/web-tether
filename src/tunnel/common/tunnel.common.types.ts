import { Logger } from "../../common/log.ts";
import { SocksDestinationAddress } from "../../proxy/socks.common.ts";

export type TunnelWriter = (
  content: Uint8Array<ArrayBuffer> | ArrayBuffer,
) => void;

export type TunnelRelayClientProxyDestination =
  | { type: "abort" }
  | {
    type: "local";
    destination: { host: string; port: number };
  }
  | {
    type: "relay";
    destination: { host: string; port: number };
    service: string;
  };

export type TunnelRelayClientOptions = {
  endpoint: URL;
  signal: AbortSignal;

  performance: {
    decryptQueueSize: number;
    connectionHandleTimeout: number;
    reconnectDelay: (context: { attempts: number; valid: boolean }) => number;
  };

  auth:
    | {
      mode: "basic";
      identifier: string;
      passkey: string;
    }
    | {
      mode: "advanced";
      serverKey: CryptoKey;
      clientKeys: CryptoKeyPair;
    };

  services: {
    proxyServer:
      | { enabled: false }
      | { enabled: true; service: string };
    proxyClient:
      | { enabled: false }
      | {
        enabled: true;
        address: Deno.TcpListenOptions;
        destination: (
          request: SocksDestinationAddress,
        ) =>
          | TunnelRelayClientProxyDestination
          | Promise<TunnelRelayClientProxyDestination>;
      };
    bind: {
      service: string;
      destination: Omit<Deno.ConnectOptions, "signal">;
    }[];
    connect: {
      service: string;
      source: Deno.TcpListenOptions;
    }[];
  };

  log: Logger;
};
