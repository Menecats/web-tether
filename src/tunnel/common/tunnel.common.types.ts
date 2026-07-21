import { Logger } from "../../common/log.ts";
import { SocksDestinationAddress } from "../../proxy/socks.common.ts";

export type TunnelListenOptions = {
  /** The port to listen on.
   *
   * Set to `0` to listen on any available port.
   */
  port: number;

  /** A literal IP address or host name that can be resolved to an IP address.
   *
   * __Note about `0.0.0.0`__ While listening `0.0.0.0` works on all platforms,
   * the browsers on Windows don't work with the address `0.0.0.0`.
   * You should show the message like `server running on localhost:8080` instead of
   * `server running on 0.0.0.0:8080` if your program supports Windows.
   *
   * @default {"0.0.0.0"} */
  hostname: string;
};

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
    reconnectDelay: (context: {
      attempts: number;
      valid: boolean;
      reason: unknown;
    }) => number | false;
  };

  auth:
    | {
      mode: "credentials";
      identifier: string;
      passkey: string;
    }
    | {
      mode: "identity";
      serverKey: CryptoKey;
      clientKeys: CryptoKeyPair;
    };

  services: {
    proxyServer: { enabled: false } | { enabled: true; service: string };
    proxyClient:
      | { enabled: false }
      | {
        enabled: true;
        address: TunnelListenOptions;
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
      source: TunnelListenOptions;
    }[];
  };

  log: Logger;
};
