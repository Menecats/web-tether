import { delay } from "@std/async/delay";
import { Logger } from "../common/log.ts";
import { verifyCryptoKeyPair } from "../common/security.ts";
import { consumableAsyncQueue } from "../common/utils.ts";
import { handleAdvancedAuthenticationClient } from "./auth/client/advanced-authentication.client.ts";
import { handleBasicAuthenticationClient } from "./auth/client/basic-authentication.client.ts";

export type CreateTunnelRelayClientOptions = {
  endpoint: URL;
  signal: AbortSignal;

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
    if (!valid) throw new Error("Invalid keys error"); // TODO
  }

  // TODO: Create local listeners

  let failed = 0;
  while (!options.signal.aborted) {
    if (failed) {
      // TODO: Delay
      // TODO: Log
      await delay(1000, { signal: options.signal });
    }

    const socket = new WebSocket(options.endpoint);
    try {
      socket.binaryType = "arraybuffer";

      const ready = Promise.withResolvers<void>();
      const queue = consumableAsyncQueue<ArrayBuffer>();
      socket.onmessage = ({ data }) => {
        if (data instanceof ArrayBuffer) queue.push(data);
      };

      socket.onopen = () =>
        queue.aborted() ? ready.reject(queue.abortReason()) : ready.resolve();
      socket.onclose = () => ready.reject(); // TODO: Reason
      socket.onerror = () => ready.reject(); // TODO: Reason

      await ready.promise;

      socket.onopen = null;
      socket.onclose = () => queue.abortWith(""); // TODO: Reason
      socket.onerror = () => queue.abortWith(""); // TODO: Reason

      const security = options.auth.mode === "basic"
        ? await handleBasicAuthenticationClient(socket, queue, options.auth)
        : await handleAdvancedAuthenticationClient(socket, queue, options.auth);

      // TODO
    } catch (err) {
      // TODO: check if is reason

      // TODO: log
      failed++;
    } finally {
    }
  }
}
