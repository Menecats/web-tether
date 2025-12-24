import { ConnectionTunnel } from "../../../common/communication.ts";
import { Logger } from "../../../common/log.ts";
import { encodeInt32 } from "../../../common/safe-buffer.ts";
import { TunnelWriter } from "../../common/tunnel.common.types.ts";
import {
  RelayCommand,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";

export async function handleClientStream({
  uid,
  write,
  tunnel,
  signal,
  log,
}: {
  uid: number;
  write: TunnelWriter;
  tunnel: ConnectionTunnel;
  signal: AbortSignal;
  log: Logger;
}) {
  const encodedUID = encodeInt32(uid);

  const reader = tunnel.readable.getReader();
  try {
    while (!signal.aborted) {
      const buffer = await reader.read();

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
  } finally {
    reader.releaseLock();
  }
}
