import { RelayCommand } from "../../server/tunnel.relay.ts";
import { TunnelClientCommandHandler } from "../tunnel.client.types.ts";

export const handle_SOCKET_CLOSED: TunnelClientCommandHandler = ({
  log,
  write,
}) => {
  log.debug(`received close command`);
  write(new Uint8Array([RelayCommand.SOCKET_CLOSE]));

  return "close-socket" as const;
};
