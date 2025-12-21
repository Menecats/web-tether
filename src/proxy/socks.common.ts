import {
  ConnectionTunnel,
  ConnectionTunnelErrorReason,
} from "../common/communication.ts";
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
  ConnectionTunnel | undefined,
  SocksHandlerBufferResponse
>;

export type SocksTunnelResponse =
  | { ok: true; tunnel: ConnectionTunnel }
  | { ok: false; error: ConnectionTunnelErrorReason };

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
