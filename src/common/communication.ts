import { TunnelWriter } from "../tunnel/common/tunnel.common.types.ts";
import { TunnelSecurity } from "../tunnel/tunnel.security.ts";
import { asyncAction } from "./async.ts";
import { Logger } from "./log.ts";
import { consumableAsyncQueue } from "./utils.ts";

export type ConnectionTunnel = {
  close(): void;

  readonly readable: ReadableStream<Uint8Array<ArrayBuffer>>;
  readonly writable: WritableStream<Uint8Array<ArrayBufferLike>>;
};
export type ConnectionTunnelErrorReason =
  | "general-failure"
  | "not-allowed"
  | "network-unreachable"
  | "host-unreachable"
  | "connection-refused"
  | "ttl-expired";

export function createConnectionTunnelPair(
  onClose?: (source: ConnectionTunnel) => void,
): [
  ConnectionTunnel,
  ConnectionTunnel,
] {
  const aToB = new TransformStream<
    Uint8Array<ArrayBuffer>,
    Uint8Array<ArrayBuffer>
  >();
  const bToA = new TransformStream<
    Uint8Array<ArrayBuffer>,
    Uint8Array<ArrayBuffer>
  >();

  const close = () => {
    try {
      bToA.readable.cancel().catch(() => {});
    } catch { /* Ignore */ }
    try {
      bToA.writable.close().catch(() => {});
    } catch { /* Ignore */ }
    try {
      aToB.readable.cancel().catch(() => {});
    } catch { /* Ignore */ }
    try {
      aToB.writable.close().catch(() => {});
    } catch { /* Ignore */ }
  };

  const tunnelA: ConnectionTunnel = {
    readable: bToA.readable,
    writable: aToB.writable,
    close: () => {
      close();
      try {
        onClose?.(tunnelA);
      } catch { /* Ignore */ }
    },
  };

  const tunnelB: ConnectionTunnel = {
    readable: aToB.readable,
    writable: bToA.writable,

    close: () => {
      close();
      try {
        onClose?.(tunnelB);
      } catch { /* Ignore */ }
    },
  };

  return [tunnelA, tunnelB];
}

export function createSocketWriter({ socket, security, signal, log }: {
  socket: WebSocket;
  security: TunnelSecurity<"client" | "relay">;
  signal: AbortSignal;
  log: Logger;
}): { write: TunnelWriter; done: Promise<unknown> } {
  const queue = consumableAsyncQueue<ArrayBuffer | Uint8Array<ArrayBuffer>>({
    signal,
  });

  const write: TunnelWriter = (data) => Promise.resolve(queue.push(data));
  const { done } = asyncAction(async () => {
    try {
      while (!signal.aborted) {
        const next = await queue.shift({ signal });
        const ciphered = await security.encrypt(next);
        socket.send(ciphered);
      }
    } catch (err) {
      log.error(`error sending data`, err);
    }
  }, { signal });

  return { done, write };
}
