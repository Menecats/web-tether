import { derivedSignal } from "./utils.ts";

export type AsyncAction = {
  abort: (reason: unknown) => void;
  done: Promise<void>;
};
export function asyncAction(
  action: (signal: AbortSignal) => Promise<void>,
  { signal }: { signal: AbortSignal },
): AsyncAction {
  const wrapped = derivedSignal(signal);

  const done = Promise
    .resolve()
    .then(() => action(wrapped.signal))
    .finally(() => {
      if (!wrapped.signal.aborted) {
        wrapped.abort();
      }
    });

  return {
    done,
    abort: (reason) => {
      if (!wrapped.signal.aborted) {
        wrapped.abort(reason);
      }
    },
  };
}
