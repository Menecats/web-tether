import {
  RelayCommand,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SERVICE_STREAM: TunnelClientCommandHandler = async (
  { buffer, write, services },
) => {
  // TODO: Should use an async action to handle this parts

  const encodedUID = buffer.data(4, { ahead: true });
  const uid = buffer.int32();
  const data = buffer.dataLeft();

  if (uid > 0) {
    const connection = services.connections.get(uid);
    if (!connection) {
      write(
        new Uint8Array([
          RelayCommand.SERVICE_CLOSED,
          ...encodedUID,
          RelayServiceConnectionReason.CONNECTION_GONE,
        ]),
      );
    } else {
      const writer = connection.tunnel.writable.getWriter();
      await writer.write(data);
      writer.releaseLock();
    }
  } else if (uid < 0) {
    const connection = services.links.get(uid);
    if (!connection) {
      write(
        new Uint8Array([
          RelayCommand.SERVICE_CLOSED,
          ...encodedUID,
          RelayServiceConnectionReason.CONNECTION_GONE,
        ]),
      );
    } else {
      const tunnel = await connection.tunnel;
      if (tunnel) {
        const writer = tunnel.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
      } else {
        write(
          new Uint8Array([
            RelayCommand.SERVICE_CLOSED,
            ...encodedUID,
            RelayServiceConnectionReason.CONNECTION_GONE,
          ]),
        );
      }
    }
  }
};
