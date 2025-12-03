import { delay } from "@std/async";

export type Logger = (
  level: "trace" | "debug" | "info" | "error",
  ...content: unknown[]
) => void;

export function concatBuffers(
  ...buffers: Array<Uint8Array | null | undefined>
) {
  const length = buffers.reduce((t, b) => t + (b?.length ?? 0), 0);
  const result = new Uint8Array(length);

  let offset = 0;
  for (let i = 0; i < buffers.length; ++i) {
    const buffer = buffers[i];
    if (!buffer) continue;

    result.set(buffer, offset);
    offset += buffer.length;
  }
  return result;
}

export function safelyClose(
  closeable: { close(): void } | undefined | null,
) {
  try {
    closeable?.close();
  } catch {
    // Ignore 'close' errors
  }
}

export function printEnum<
  T extends number,
  E extends Record<number, string>,
>(
  e: E,
  k: T,
) {
  return e[k] || `<unknown:${k}>`;
}

export type ConsumableAsyncQueue<Input, Output> = Disposable & {
  disposed: () => boolean;

  queued: () => number;
  waitFor: (event: "enqueue" | "dequeue") => Promise<void>;

  push(item: Input): void;
  shift(): Promise<Output>;
};

export function consumableAsyncQueue<Item>(): ConsumableAsyncQueue<Item, Item>;
export function consumableAsyncQueue<Input, Output>(
  map: (value: Input, signal: AbortSignal) => Output | Promise<Output>,
): ConsumableAsyncQueue<Input, Output>;
export function consumableAsyncQueue<Input, Output>(
  map?: (value: Input, signal: AbortSignal) => Output | Promise<Output>,
): ConsumableAsyncQueue<Input, Output> {
  if (!map) map = (item: Input) => item as unknown as Output;

  type Value =
    | { success: true; content: Output }
    | { success: false; reason: unknown };

  const waiting: Array<PromiseWithResolvers<Output>> = [];
  const pending: Array<Value> = [];

  const enqueueListeners: Array<PromiseWithResolvers<void>> = [];
  const dequeueListeners: Array<PromiseWithResolvers<void>> = [];

  let operation = Promise.resolve();

  let queued = 0;

  const abortController = new AbortController();

  return {
    disposed: () => abortController.signal.aborted,
    [Symbol.dispose]: () => {
      abortController.abort();

      queued = 0;
      pending.length = 0;

      waiting.forEach((w) => w.reject());
      waiting.length = 0;

      enqueueListeners.forEach((l) => l.reject());
      enqueueListeners.length = 0;

      dequeueListeners.forEach((l) => l.reject());
      dequeueListeners.length = 0;
    },

    queued: () => queued,
    waitFor: (event) => {
      const promise = Promise.withResolvers<void>();

      if (event === "enqueue") enqueueListeners.push(promise);
      else dequeueListeners.push(promise);

      return promise.promise;
    },

    push: (item) => {
      if (abortController.signal.aborted) return;

      queued++;

      enqueueListeners.forEach((l) => l.resolve());
      enqueueListeners.length = 0;

      const process = Promise
        .resolve()
        .then(async () => await map(item, abortController.signal));

      operation = operation
        .then(async () => {
          let value: Value;
          try {
            value = { success: true, content: await process };
          } catch (err) {
            value = { success: false, reason: err };
          }

          if (abortController.signal.aborted) return;

          if (waiting.length) {
            dequeueListeners.forEach((l) => l.resolve());
            dequeueListeners.length = 0;
            queued--;

            const next = waiting.shift()!;

            if (value.success) next.resolve(value.content);
            else next.reject(value.reason);
          } else {
            pending.push(value);
          }
        });
    },
    shift: () => {
      if (abortController.signal.aborted) return Promise.reject();

      if (pending.length) {
        dequeueListeners.forEach((l) => l.resolve());
        dequeueListeners.length = 0;
        queued--;

        const value = pending.shift()!;
        return value.success
          ? Promise.resolve(value.content)
          : Promise.reject(value.reason);
      }

      const wait = Promise.withResolvers<Output>();
      waiting.push(wait);
      return wait.promise;
    },
  };
}

export async function pbkdf2Hash512(
  plaintext: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    plaintext,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 200_000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  return derivedBits;
}

export function encodeIV(role: "server" | "client", counter: bigint) {
  const iv = new Uint8Array(12);
  const view = new DataView(iv.buffer);

  counter = counter % (2n ** 88n);

  const high = counter >> 64n;
  const low = counter & (2n ** 64n - 1n);

  view.setUint32(0, Number(high));
  view.setBigUint64(4, low);

  iv[0] = role === "server" ? 0x01 : 0x02;

  return iv;
}

export function assertEnabled<T extends { enabled: boolean }>(
  value: T,
): asserts value is T & { enabled: true } {
  if (!value.enabled) throw new Error("Not enabled");
}

export function randomWait(min: number, max: number, signal?: AbortSignal) {
  return delay(min + Math.random() * Math.round(max - min), {
    persistent: false,
    signal,
  });
}
