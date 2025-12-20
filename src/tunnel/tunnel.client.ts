import { delay } from "@std/async/delay";
import { Logger, prefixLogger } from "../common/log.ts";
import { safeReader } from "../common/safe-buffer.ts";
import { verifyCryptoKeyPair } from "../common/security.ts";
import { consumableAsyncQueue } from "../common/utils.ts";
import { handleAdvancedAuthenticationClient } from "./auth/client/advanced-authentication.client.ts";
import { handleBasicAuthenticationClient } from "./auth/client/basic-authentication.client.ts";
import { TunnelClientError } from "./tunnel.errors.ts";
import { RelayCommand } from "./tunnel.relay.ts";

export type CreateTunnelRelayClientOptions = {
  endpoint: URL;
  signal: AbortSignal;

  performance: {
    decryptQueueSize: number;
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

  log: Logger;
};
export async function createTunnelRelayClient(
  options: CreateTunnelRelayClientOptions,
) {
  if (options.auth.mode === "advanced") {
    const valid = await verifyCryptoKeyPair(
      options.auth.clientKeys,
    );
    if (!valid) {
      throw new TunnelClientError({
        reason: "invalid-configuration",
        details: "client-keys",
      });
    }
  }

  // TODO: Create local listeners

  let connectedOnce = false;
  let failed = 0;

  while (!options.signal.aborted) {
    if (failed) {
      const waitDelay = options.performance.reconnectDelay({
        attempts: failed,
        valid: connectedOnce,
      });

      options.log.debug(
        `delay connection after #${failed} failed attempt(s), waiting ${waitDelay}ms`,
      );

      await delay(waitDelay, { signal: options.signal });
    }

    options.log.debug(`connecting to '${options.endpoint}'`);

    const log = prefixLogger(options.log, "[socket]");

    const socket = new WebSocket(options.endpoint);
    socket.binaryType = "arraybuffer";

    try {
      await handleSocket(
        socket,
        options,
        log,
        () => {
          connectedOnce = true;
          failed = 0;
        },
      );
    } catch (err) {
      log.error("error handling socket", err);
      failed++;
    } finally {
      socket.close();
    }
  }
}

async function handleSocket(
  socket: WebSocket,
  options: Omit<CreateTunnelRelayClientOptions, "log">,
  log: Logger,
  success: () => void,
) {
  try {
    using queue = consumableAsyncQueue<ArrayBuffer>({ signal: options.signal });
    const ready = Promise.withResolvers<void>();

    log.trace(`configuring 'ready' listeners`);

    socket.onmessage = ({ data }) => {
      if (data instanceof ArrayBuffer) queue.push(data);
    };
    socket.onopen = () =>
      queue.aborted() ? ready.reject(queue.abortReason()) : ready.resolve();
    socket.onclose = () =>
      ready.reject(new TunnelClientError({ reason: "socket-closed" }));
    socket.onerror = (event) =>
      ready.reject(
        new TunnelClientError({
          reason: "socket-error",
          error: ("error" in event) ? event.error : event,
        }),
      );

    log.trace(`waiting for socket to connect`);
    await ready.promise;
    log.debug(`connected`);

    log.trace(`configuring 'abort' listeners`);
    socket.onopen = null;
    socket.onclose = () =>
      queue.abortWith(new TunnelClientError({ reason: "socket-closed" }));
    socket.onerror = (event) =>
      queue.abortWith(
        new TunnelClientError({
          reason: "socket-error",
          error: ("error" in event) ? event.error : event,
        }),
      );

    log.trace(`perform handshake`);
    const security = options.auth.mode === "basic"
      ? await handleBasicAuthenticationClient(
        socket,
        queue,
        options.auth,
        prefixLogger(log, "[basic]"),
      )
      : await handleAdvancedAuthenticationClient(
        socket,
        queue,
        options.auth,
        prefixLogger(log, "[advanced]"),
      );

    success();

    log.trace(`configure decrypted queue`);
    using decryptQueue = consumableAsyncQueue<ArrayBuffer, ArrayBuffer>({
      signal: options.signal,
      map: (packet, signal) => security.decrypt(packet, signal),
    });

    (async () => {
      try {
        while (true) {
          const encryptedPacket = await queue.shift();
          if (decryptQueue.queued() >= options.performance.decryptQueueSize) {
            await decryptQueue.waitFor("dequeue");
          }
          decryptQueue.push(encryptedPacket);
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
    })();

    log.trace(`ready, waiting commands`);

    while (!options.signal.aborted) {
      const buffer = safeReader(
        await decryptQueue.shift(),
        () => new TunnelClientError({ reason: "buffer-too-short" }),
      );

      const command = buffer.uint8();

      switch (command) {
        case RelayCommand.SOCKET_CLOSE: {
          log.debug(`received close command`);
          socket.send(new Uint8Array([RelayCommand.SOCKET_CLOSE]));
          return;
        }

          // TODO: Handle all commands
      }
    }
  } finally {
    // TODO: Close all live connections
  }
}
