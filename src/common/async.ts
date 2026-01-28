import { deriveSignal } from "./utils.ts";

export type AsyncAction = {
  abort: (reason: unknown) => void;
  done: Promise<void>;
  ready: Promise<void>;
};
export type AsyncActionContext = {
  signal: AbortSignal;
  ready: () => void;
};

export function asyncAction(
  action: (context: AsyncActionContext) => Promise<void>,
  { signal }: { signal: AbortSignal },
): AsyncAction {
  const wrapped = deriveSignal(signal);

  const ready = Promise.withResolvers<void>();
  const done = Promise.resolve()
    .then(() => {
      return action({
        signal: wrapped.signal,
        ready: () => ready.resolve(),
      });
    })
    .finally(() => {
      ready.resolve();
      wrapped.abort();
    });

  return {
    done,
    ready: ready.promise,
    abort: (reason) => {
      if (!wrapped.signal.aborted) {
        wrapped.abort(reason);
      }
    },
  };
}
