import { printEnum } from "../../../common/utils.ts";
import { RelayBindReply } from "../../server/tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SERVICE_BIND: TunnelClientCommandHandler = ({
  buffer,
  log,
}) => {
  const reply = buffer.uint8();
  if (reply === RelayBindReply.SUCCESS) {
    log.info("bind successful");
  } else {
    log.error(`bind errored: ${printEnum(RelayBindReply, reply)}`);
  }
};
