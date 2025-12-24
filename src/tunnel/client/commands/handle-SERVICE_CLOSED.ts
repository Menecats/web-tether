import { printEnum } from "../../../common/utils.ts";
import { RelayServiceConnectionReason } from "../../tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SERVICE_CLOSED: TunnelClientCommandHandler = (
  { buffer, log, services },
) => {
  const uid = buffer.int32();
  const reason = buffer.uint8();

  log.trace(
    `closing connection [${uid}] with reason '${
      printEnum(RelayServiceConnectionReason, reason)
    }'`,
  );

  if (uid > 0) {
    services.connections.get(uid)?.close(reason);
  } else if (uid < 0) {
    services.links.get(uid)?.close(reason);
  }
};
