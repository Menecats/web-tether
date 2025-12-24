import { Logger, prefixLogger } from "../../../common/log.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { handleClientAdvancedAuthentication } from "./advanced-authentication.client.ts";
import { handleClientBasicAuthentication } from "./basic-authentication.client.ts";

export type HandleClientAuthenticationOptions = {
  socket: WebSocket;
  queue: ConsumableAsyncQueue<ArrayBuffer>;
  auth: TunnelRelayClientOptions["auth"];
  log: Logger;
};
export async function handleClientAuthentication(
  { socket, queue, auth, log }: HandleClientAuthenticationOptions,
) {
  return auth.mode === "basic"
    ? await handleClientBasicAuthentication({
      socket,
      queue,
      auth,
      log: prefixLogger(log, "[basic]"),
    })
    : await handleClientAdvancedAuthentication({
      socket,
      queue,
      auth,
      log: prefixLogger(log, "[advanced]"),
    });
}
