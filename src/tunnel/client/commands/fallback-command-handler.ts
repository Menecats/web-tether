import { printEnum } from "../../../common/utils.ts";
import { RelayCommand } from "../../server/tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const fallbackCommandHandler: TunnelClientCommandHandler = ({
  command,
  log,
  write,
}) => {
  log.warn(`received unsupported command: ${printEnum(RelayCommand, command)}`);
  write(new Uint8Array([RelayCommand.UNSUPPORTED, command]));
};
