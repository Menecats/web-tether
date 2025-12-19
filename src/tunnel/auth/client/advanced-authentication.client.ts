import {
  safeReadUint8,
  safeReadWithLength8,
  writeWithLength16,
} from "../../../common/safe-buffer.ts";
import { deriveRawSecret, deriveSessionKey } from "../../../common/security.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { CreateTunnelRelayClientOptions } from "../../tunnel.client.ts";
import { RelayAuthentication, RelayVersion7 } from "../../tunnel.const.ts";
import { createTunnelSecurity, TunnelSecurity } from "../../tunnel.security.ts";

export async function handleAdvancedAuthenticationClient(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayClientOptions["auth"] & { mode: "advanced" },
): Promise<TunnelSecurity<"client">> {
  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.ADVANCED_AUTH,
      ...await writeWithLength16(
        await crypto.subtle.exportKey(
          "raw",
          auth.clientKeys.publicKey,
        ),
      ),
    ]),
  );

  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);

  const sharedSecret = await deriveRawSecret(
    auth.clientKeys.privateKey,
    auth.serverKey,
  );

  const challenge = new Uint8Array(await queue.shift());

  let offset = 0;

  const [version, versionLength] = safeReadUint8(
    challenge.subarray(offset),
    () => new Error("not enough buffer"), // TODO
  );
  offset += versionLength;

  if (version !== RelayVersion7) {
    throw new Error("invalid version");
  }

  const [authResult, authResultLength] = safeReadUint8(
    challenge.subarray(offset),
    () => new Error("not enough buffer"), // TODO
  );
  offset += authResultLength;

  if (authResult === RelayAuthentication.UNSUPPORTED_AUTH) {
    // TODO: log fail
    throw new Error("fail"); // TODO: Error
  }

  if (authResult !== RelayAuthentication.ADVANCED_AUTH) {
    // TODO: log fail
    throw new Error("fail"); // TODO: Error
  }

  const [sessionSalt, sessionSaltLength] = safeReadWithLength8(
    challenge.subarray(offset),
    () => new Error("not enough buffer"), // TODO: Error
  );
  offset += sessionSaltLength;

  const [encryptedChallenge, encryptedChallengeLength] = safeReadWithLength8(
    challenge.subarray(offset),
    () => new Error("not enough buffer"), // TODO: Error
  );
  offset += encryptedChallengeLength;

  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  const security = createTunnelSecurity("client", sessionKey);

  const decryptedChallenge = new Uint8Array(
    await security.decrypt(encryptedChallenge),
  );

  socket.send(
    await security.encrypt(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.ADVANCED_AUTH,

        ...decryptedChallenge,
      ]),
    ),
  );

  return security;
}
