import {
  ConnectionTunnel,
  ConnectionTunnelErrorReason,
} from "../../common/communication.ts";
import { Logger } from "../../common/log.ts";
import { SafeReader } from "../../common/safe-buffer.ts";
import { TunnelWriter } from "../common/tunnel.common.types.ts";
import {
  RelayCommand,
  RelayServiceConnectionReason,
  RelayServiceType,
} from "../tunnel.relay.ts";

export type TunnelClientCommandHandlerOptions = {
  encoder: TextEncoder;
  decoder: TextDecoder;

  command: RelayCommand;
  buffer: SafeReader;
  write: TunnelWriter;

  services: {
    registered: Map<
      string,
      | {
        type: RelayServiceType.SOCKS_PROXY;
        service: string;
      }
      | {
        type: RelayServiceType.RAW_SOCKET;
        service: string;
        destination: Omit<Deno.ConnectOptions, "signal">;
      }
    >;

    connections: Map<number, TunnelClientConnection>;
    links: Map<number, TunnelClientLink>;
  };
  signal: AbortSignal;

  log: Logger;
};

export type TunnelClientCommandHandlerResult = void | "close-socket";
export type TunnelClientCommandHandler = (
  options: TunnelClientCommandHandlerOptions,
) =>
  | TunnelClientCommandHandlerResult
  | Promise<TunnelClientCommandHandlerResult>;

export type TunnelClientConnection = {
  readonly uid: number;
  readonly tunnel: ConnectionTunnel;

  readonly onConnect: () => void;
  readonly onError: (reason: ConnectionTunnelErrorReason) => void;

  readonly close: (reason: RelayServiceConnectionReason) => void;
  readonly done: Promise<void>;
};
export type TunnelClientLink = {
  readonly uid: number;
  readonly tunnel: Promise<ConnectionTunnel | undefined>;

  readonly close: (reason: RelayServiceConnectionReason) => void;
  readonly done: Promise<void>;
};
