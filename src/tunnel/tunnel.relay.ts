import { delay } from "@std/async";
import { consumableAsyncQueue, safelyClose } from "../utils.ts";
import { handleAdvencedAuthenticationMode } from "./auth/advanced-authentication.ts";
import { handleBasicAuthenticationMode } from "./auth/basic-authentication.ts";
import type { CreateTunnelRelayOptions } from "./tunnel.server.ts";
import { RelayAuthentication, RelayVersion7 } from "./tunnel.const.ts";
import { RelaySecurity } from "./tunnel.security.ts";

export type RelayRequest = { timeout: number };
export type RelayPacket = { buffer: Uint8Array<ArrayBuffer>; view: DataView };

export type RelayHandler = AsyncGenerator<
  RelayRequest,
  RelaySecurity | undefined,
  RelayPacket
>;

async function* authenticateRelay(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
): RelayHandler {
  // Determine protocol version
  const packet = yield { timeout: 1000 }; // TODO: Define timeout
  if (packet.buffer[0] !== RelayVersion7) return;

  const authMode = packet.buffer[1];

  const authPacket = {
    buffer: packet.buffer.subarray(2),
    view: new DataView(
      packet.buffer.buffer,
      packet.buffer.byteOffset + 2,
      packet.buffer.byteLength - 2,
    ),
  } satisfies RelayPacket;

  if (authMode === RelayAuthentication.BASIC_AUTH) {
    if (options.auth.basic.enabled) {
      return yield* handleBasicAuthenticationMode(
        options,
        socket,
        authPacket,
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return;
    }
  }

  if (authMode === RelayAuthentication.ADVANCED_AUTH) {
    if (options.auth.advanced.enabled) {
      return yield* handleAdvencedAuthenticationMode(
        options,
        socket,
        authPacket,
      );
    } else {
      socket.send(
        new Uint8Array([
          RelayVersion7,
          RelayAuthentication.UNSUPPORTED_AUTH,
        ]),
      );
      return;
    }
  }

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.UNSUPPORTED_AUTH,
    ]),
  );
}

export async function handleSocketRelay(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
) {
  try {
    // Create received messages queue
    using queue = consumableAsyncQueue<ArrayBuffer>();

    socket.binaryType = "arraybuffer";
    socket.onmessage = ({ data }) => {
      if (!(data instanceof ArrayBuffer)) return queue[Symbol.dispose]();

      queue.push(data);
    };

    // Wait for socket to open
    const opened = Promise.withResolvers<void>();
    socket.onopen = () => queue.disposed() ? opened.reject() : opened.resolve();
    socket.onclose = () => opened.reject();
    socket.onerror = () => opened.reject();
    await opened.promise;

    // Track closure or errors
    socket.onopen = null;
    socket.onclose = () => queue[Symbol.dispose]();
    socket.onerror = () => queue[Symbol.dispose]();

    const relayHandler = authenticateRelay(options, socket);

    let request: RelayRequest | undefined;
    let security: RelaySecurity | undefined;

    while (true) {
      if (options.signal.aborted) {
        await relayHandler.throw("interrupted"); // TODO
        return;
      }

      let buffer: ArrayBuffer;
      if (!request) {
        buffer = new ArrayBuffer(0);
      } else {
        try {
          buffer = await Promise.race([
            queue.shift(),
            delay(request.timeout, {
              persistent: false,
              signal: options.signal,
            }).catch(() => {
              throw "interrupted"; // TODO
            }).then(() => {
              throw "timed-out"; // TODO
            }),
          ]);
        } catch (err) {
          await relayHandler.throw(err);
          return;
        }
      }

      const result = await relayHandler.next({
        buffer: new Uint8Array(buffer),
        view: new DataView(buffer),
      });
      if (result.done) {
        request = undefined;
        security = result.value;
        break;
      }

      request = result.value;
    }

    // Security must be configured to proceed
    if (!security) return;

    using decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>(
      (packet, signal) => security.decrypt(packet, signal),
    );

    (async () => {
      try {
        while (true) {
          const encryptedPacket = await queue.shift();

          if (decryptQueue.queued() >= options.auth.queueSize) {
            await decryptQueue.waitFor("dequeue");
          }
          decryptQueue.push(encryptedPacket);
        }
      } finally {
        decryptQueue[Symbol.dispose]();
      }
    })();

    while (true) {
      const packet = await decryptQueue.shift();

      // TODO: Process packet
    }
  } finally {
    socket.onopen = null;
    socket.onclose = null;
    socket.onerror = null;
    socket.onmessage = null;

    safelyClose(socket);
  }
}
