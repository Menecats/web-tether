import { delay } from "@std/async";

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

export type ConsumableAsyncQueue<Input, Output = Input> = Disposable & {
  aborted: () => boolean;

  abortWith: (reason: unknown) => void;
  abortReason: () => unknown;

  queued: () => number;
  waitFor: (event: "enqueue" | "dequeue") => Promise<void>;

  push(item: Input): void;
  shift(
    options?: {
      timeout?: number;
      timeoutError?: () => unknown;
    },
  ): Promise<Output>;
};

export function consumableAsyncQueue<Item>(options?: {
  signal?: AbortSignal;
  map?: (value: Item, signal: AbortSignal) => Item | Promise<Item>;
}): ConsumableAsyncQueue<Item, Item>;
export function consumableAsyncQueue<Input, Output>(options: {
  signal?: AbortSignal;
  map: (value: Input, signal: AbortSignal) => Output | Promise<Output>;
}): ConsumableAsyncQueue<Input, Output>;
export function consumableAsyncQueue<Input, Output>(
  options?: {
    signal?: AbortSignal;
    signalError?: () => unknown;
    map?: (value: Input, signal: AbortSignal) => Output | Promise<Output>;
  },
): ConsumableAsyncQueue<Input, Output> {
  const map = options?.map ?? ((item: Input) => item as unknown as Output);

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

  const queue = {
    aborted: () => abortController.signal.aborted,
    abortWith: (reason) => {
      options?.signal?.removeEventListener("abort", onAbort);

      abortController.abort(reason);

      queued = 0;
      pending.length = 0;

      waiting.forEach((w) => w.reject(reason));
      waiting.length = 0;

      enqueueListeners.forEach((l) => l.reject(reason));
      enqueueListeners.length = 0;

      dequeueListeners.forEach((l) => l.reject(reason));
      dequeueListeners.length = 0;
    },
    abortReason: () => {
      if (!queue.aborted()) throw new Error("Queue not aborted");
      return abortController.signal.reason;
    },

    [Symbol.dispose]: () => queue.abortWith(undefined),

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
    shift: ({ timeout = -1, timeoutError } = {}) => {
      if (abortController.signal.aborted) {
        return Promise.reject(abortController.signal.reason);
      }

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

      const timeoutTimer = timeout > 0
        ? setTimeout(() => {
          const index = waiting.indexOf(wait);
          if (index >= 0) waiting.splice(index, 1);

          wait.reject(timeoutError ? timeoutError() : new Error("timeout"));
        }, timeout)
        : undefined;

      return wait.promise.finally(() => {
        if (timeoutTimer) clearTimeout(timeoutTimer);
      });
    },
  } satisfies ConsumableAsyncQueue<Input, Output>;

  const onAbort = () => queue.abortWith(options!.signal!.reason);
  options?.signal?.addEventListener("abort", onAbort, { once: true });

  return queue;
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
