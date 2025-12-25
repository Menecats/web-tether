import {
  RelayCommand,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SERVICE_STREAM: TunnelClientCommandHandler = (
  { buffer, write, services },
) => {
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
      connection.write(data);
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
      connection.write(data);
    }
  }
};
