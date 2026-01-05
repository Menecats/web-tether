import { Logger, prefixLogger } from "../../../common/log.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { handleClientCredentialsAuthentication } from "./credentials-authentication.client.ts";
import { handleClientIdentityAuthentication } from "./identity-authentication.client.ts";

export type HandleClientAuthenticationOptions = {
  socket: WebSocket;
  queue: ConsumableAsyncQueue<ArrayBuffer>;
  auth: TunnelRelayClientOptions["auth"];
  log: Logger;
};
export async function handleClientAuthentication({
  socket,
  queue,
  auth,
  log,
}: HandleClientAuthenticationOptions) {
  return auth.mode === "credentials"
    ? await handleClientCredentialsAuthentication({
      socket,
      queue,
      auth,
      log: prefixLogger(log, "[credentials]"),
    })
    : await handleClientIdentityAuthentication({
      socket,
      queue,
      auth,
      log: prefixLogger(log, "[identity]"),
    });
}
