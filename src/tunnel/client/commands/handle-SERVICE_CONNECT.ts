import { ConnectionTunnelErrorReason } from "../../../common/communication.ts";
import { printEnum } from "../../../common/utils.ts";
import {
  RelayCommand,
  RelayConnectReply,
  RelayServiceConnectionReason,
} from "../../tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SERVICE_CONNECT: TunnelClientCommandHandler = (
  { buffer, write, services, log },
) => {
  log.trace(`received connect response`);

  const encodedUID = buffer.data(4, { ahead: true });
  const uid = buffer.int32();

  const reply = buffer.uint8();

  log.trace(
    `connect [${uid}]: ${printEnum(RelayConnectReply, reply)}`,
  );

  const service = services.connections.get(uid);
  if (reply === RelayConnectReply.SUCCESS) {
    if (service) {
      service.onConnect();
    } else {
      write(
        new Uint8Array([
          RelayCommand.SERVICE_CLOSED,
          ...encodedUID,
          RelayServiceConnectionReason.CONNECTION_GONE,
        ]),
      );
    }
  } else if (service) {
    let reason: ConnectionTunnelErrorReason;

    switch (reply) {
      case RelayConnectReply.CONNECT_NOT_ALLOWED:
        reason = "not-allowed";
        break;
      case RelayConnectReply.CONNECT_NETWORK_UNREACHABLE:
        reason = "network-unreachable";
        break;
      case RelayConnectReply.CONNECT_HOST_UNREACHABLE:
        reason = "host-unreachable";
        break;
      case RelayConnectReply.CONNECT_CONNECTION_REFUSED:
        reason = "connection-refused";
        break;
      case RelayConnectReply.CONNECT_TTL_EXPIRED:
        reason = "ttl-expired";
        break;
      default:
        reason = "general-failure";
    }

    service.onError(reason);
    service.close(RelayServiceConnectionReason.TRANSPORT_SOCKET_START_FAILED);
  }
};
