import { Logger } from "../../common/log.ts";

export type TunnelWriter = (
  content: Uint8Array<ArrayBuffer> | ArrayBuffer,
) => Promise<void>;

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
    proxyClient: {
      service: string;
      address: Deno.TcpListenOptions;
    }[];
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
