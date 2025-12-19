import { Logger } from "../common/log.ts";

export type SocksDestinationAddress = {
  mode: "ipv4" | "ipv6" | "domain";
  host: string;
  port: number;
};

export type SocksHandlerBufferRequest =
  | { timeout: number; size: number; doNotConsume?: true }
  | { timeout: number; until: number; doNotConsume?: true };
export type SocksHandlerBufferResponse = { buffer: Uint8Array; view: DataView };

export type SocksHandler = AsyncGenerator<
  SocksHandlerBufferRequest,
  SocksTunnel | undefined,
  SocksHandlerBufferResponse
>;

export type SocksTunnel = {
  close(): void;

  readonly readable: ReadableStream<Uint8Array<ArrayBuffer>>;
  readonly writable: WritableStream<Uint8Array<ArrayBufferLike>>;
};

export type SocksTunnelError =
  | "general-failure"
  | "not-allowed"
  | "network-unreachable"
  | "host-unreachable"
  | "connection-refused"
  | "ttl-expired";
export type SocksTunnelResponse =
  | { ok: true; tunnel: SocksTunnel }
  | { ok: false; error: SocksTunnelError };

export type SocksTunneler = (
  destination: SocksDestinationAddress,
  log: Logger,
) => Promise<SocksTunnelResponse>;

export const SOCKS_HANDSHAKE_INIT_TIMEOUT = 10000;
export const SOCKS_HANDSHAKE_TIMEOUT = 100;
export const SOCKS_AUTH_INIT_TIMEOUT = 10000;
export const SOCKS_AUTH_TIMEOUT = 100;
export const SOCKS_REQUEST_INIT_TIMEOUT = 10000;
export const SOCKS_REQUEST_TIMEOUT = 10000;
