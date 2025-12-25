import { abortable } from "@std/async/abortable";
import { asyncAction } from "../../../common/async.ts";
import { ConnectionTunnel } from "../../../common/communication.ts";
import { Logger } from "../../../common/log.ts";
import { encodeInt32 } from "../../../common/safe-buffer.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { TunnelWriter } from "../../common/tunnel.common.types.ts";
import {
  RelayCommand,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";

export function handleClientStream({
  uid,
  write,
  tunnel,
  signal,
  log,
  outputQueue,
}: {
  uid: number;
  write: TunnelWriter;
  tunnel: ConnectionTunnel;
  signal: AbortSignal;
  log: Logger;
  outputQueue: ConsumableAsyncQueue<Uint8Array<ArrayBuffer>>;
}) {
  const encodedUID = encodeInt32(uid);

  const writeActionDone = Symbol("read action done");
  const readActionDone = Symbol("read action done");

  const writeAction = asyncAction(async (writeSignal) => {
    const writer = tunnel.writable.getWriter();
    try {
      while (!writeSignal.aborted) {
        const next = await outputQueue.shift({ signal: writeSignal });
        await writer.write(next);
      }
    } catch (err) {
      if (err !== readActionDone) {
        if (!(err instanceof Deno.errors.Interrupted)) {
          log.trace(
            `connection closed unexpectedly, notifying closure`,
            err,
          );
        }

        const reason = err instanceof Deno.errors.Interrupted
          ? RelayServiceConnectionReason.TRANSPORT_SOCKET_INTERRUPTED
          : err instanceof Deno.errors.UnexpectedEof
          ? RelayServiceConnectionReason.TRANSPORT_SOCKET_EOS
          : RelayServiceConnectionReason.UNKNOWN;

        write(
          new Uint8Array([
            RelayCommand.SERVICE_CLOSED,
            ...encodedUID,
            reason,
          ]),
        );
      }
    } finally {
      writer.releaseLock();
      readAction.abort(writeActionDone);
    }
  }, { signal });

  const readAction = asyncAction(async (readSignal) => {
    const reader = tunnel.readable.getReader();
    try {
      while (!readSignal.aborted) {
        const buffer = await abortable(reader.read(), readSignal);

        if (buffer.value) {
          const output = new Uint8Array(5 + buffer.value.length);
          output[0] = RelayCommand.SERVICE_STREAM;
          output.set(encodedUID, 1);
          output.set(buffer.value, 5);
          write(output);
        }

        if (buffer.done) break;
      }

      log.trace(
        `connection closed cleanly, notifying closure`,
      );

      write(
        new Uint8Array([
          RelayCommand.SERVICE_CLOSED,
          ...encodedUID,
          RelayServiceConnectionReason.TRANSPORT_SOCKET_CLOSED,
        ]),
      );
    } catch (err) {
      if (err !== writeActionDone) {
        if (!(err instanceof Deno.errors.Interrupted)) {
          log.trace(
            `connection closed unexpectedly, notifying closure`,
            err,
          );
        }

        const reason = err instanceof Deno.errors.Interrupted
          ? RelayServiceConnectionReason.TRANSPORT_SOCKET_INTERRUPTED
          : err instanceof Deno.errors.UnexpectedEof
          ? RelayServiceConnectionReason.TRANSPORT_SOCKET_EOS
          : RelayServiceConnectionReason.UNKNOWN;

        write(
          new Uint8Array([
            RelayCommand.SERVICE_CLOSED,
            ...encodedUID,
            reason,
          ]),
        );
      }
    } finally {
      reader.releaseLock();
      writeAction.abort(readActionDone);
    }
  }, { signal });

  return Promise.all([
    writeAction.done,
    readAction.done,
  ]);
}
