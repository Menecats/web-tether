import { printEnum } from "../../../common/utils.ts";
import { RelayCommand } from "../../server/tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_UNSUPPORTED: TunnelClientCommandHandler = ({
  buffer,
  log,
}) => {
  const unsupportedCommand = buffer.uint8();
  log.error(
    `server notified unsupported command: ${
      printEnum(
        RelayCommand,
        unsupportedCommand,
      )
    }`,
  );
};
