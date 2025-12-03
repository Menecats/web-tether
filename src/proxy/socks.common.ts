import { Logger } from "../utils.ts";

export type SocksDestinationAddress = {
  mode: "ipv4" | "ipv6" | "domain";
  host: string;
  port: number;
};

export type SocksHandlerBufferRequest =
  | { size: number; doNotConsume?: true }
  | { until: number; doNotConsume?: true };
export type SocksHandlerBufferResponse = { buffer: Uint8Array; view: DataView };

export type SocksHandler = AsyncGenerator<
  SocksHandlerBufferRequest,
  SocksTunnel | undefined,
  SocksHandlerBufferResponse
>;

export type SocksTunnel = {
  close(): void;

  write(p: Uint8Array): Promise<number>;
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
