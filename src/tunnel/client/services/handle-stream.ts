import { abortable } from "@std/async/abortable";
import { asyncAction } from "../../../common/async.ts";
import { ConnectionTunnel } from "../../../common/communication.ts";
import { Logger, prefixLogger } from "../../../common/log.ts";
import { encodeInt32 } from "../../../common/safe-buffer.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { TunnelWriter } from "../../common/tunnel.common.types.ts";
import {
  RelayCommand,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";

export const streamClosed = Symbol("stream closed");

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

  const writeActionDone = Symbol("write action done");
  const readActionDone = Symbol("read action done");

  const writeLog = prefixLogger(log, "[write]");
  const writeAction = asyncAction(async (writeSignal) => {
    const writer = tunnel.writable.getWriter();
    try {
      while (!writeSignal.aborted) {
        const next = await outputQueue.shift({ signal: writeSignal });
        await writer.write(next);
      }
    } catch (err) {
      if (err === readActionDone || err === streamClosed) {
        writeLog.trace(`connection terminated`);
      } else {
        if (!(err instanceof Deno.errors.Interrupted)) {
          writeLog.trace(
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

  const readLog = prefixLogger(log, "[read]");
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

      readLog.trace(
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
      if (err === writeActionDone || err === streamClosed) {
        readLog.trace(`connection terminated`);
      } else {
        if (!(err instanceof Deno.errors.Interrupted)) {
          readLog.trace(
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
