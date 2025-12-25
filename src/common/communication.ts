import { TunnelWriter } from "../tunnel/common/tunnel.common.types.ts";
import { TunnelClientError } from "../tunnel/tunnel.errors.ts";
import { TunnelSecurity } from "../tunnel/tunnel.security.ts";
import { asyncAction } from "./async.ts";
import { Logger } from "./log.ts";
import { ConsumableAsyncQueue, consumableAsyncQueue } from "./utils.ts";

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

export function createDecipheredQueue(
  { cipheredQueue: queue, security, signal, decryptQueueSize }: {
    cipheredQueue: ConsumableAsyncQueue<ArrayBuffer>;
    security: TunnelSecurity<"client" | "relay">;
    signal: AbortSignal;
    decryptQueueSize: number;
  },
) {
  const decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>({
    signal,
    map: (packet, queueSignal) => security.decrypt(packet, queueSignal),
  });

  asyncAction(async (actionSignal) => {
    try {
      while (!actionSignal.aborted) {
        const encryptedPacket = await queue.shift({ signal: actionSignal });
        if (decryptQueue.queued() >= decryptQueueSize) {
          await decryptQueue.waitFor("dequeue", { signal: actionSignal });
        }

        if (!actionSignal.aborted) {
          decryptQueue.push(encryptedPacket);
        }
      }
    } catch (error) {
      if (!queue.aborted()) {
        queue.abortWith(
          (error instanceof TunnelClientError)
            ? error
            : new TunnelClientError({ reason: "unknown-error", error }),
        );
      }

      decryptQueue.abortWith(queue.abortReason());
    }
  }, { signal });

  return decryptQueue;
}

export function createCipheredWriter({ socket, security, signal, log }: {
  socket: WebSocket;
  security: TunnelSecurity<"client" | "relay">;
  signal: AbortSignal;
  log: Logger;
}): { write: TunnelWriter; done: Promise<unknown> } {
  const queue = consumableAsyncQueue<ArrayBuffer | Uint8Array<ArrayBuffer>>({
    signal,
  });

  const write: TunnelWriter = (data) => queue.push(data);
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
