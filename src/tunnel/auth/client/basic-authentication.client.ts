import {
  safeReadUint8,
  safeReadWithLength8,
} from "../../../common/safe-buffer.ts";
import { pbkdf2Hash512 } from "../../../common/security.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { CreateTunnelRelayClientOptions } from "../../tunnel.client.ts";
import { RelayAuthentication, RelayVersion7 } from "../../tunnel.const.ts";
import { createTunnelSecurity, TunnelSecurity } from "../../tunnel.security.ts";

export async function handleBasicAuthenticationClient(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayClientOptions["auth"] & { mode: "basic" },
): Promise<TunnelSecurity<"client">> {
  const encoder = new TextEncoder();

  const encodedIdentifier = encoder.encode(auth.identifier);

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.BASIC_AUTH,

      encodedIdentifier.length,
      ...encodedIdentifier,
    ]),
  );

  const challenge = new Uint8Array(await queue.shift()); // TODO: Timeout

  let offset = 0;

  const [version, versionLength] = safeReadUint8(
    challenge.subarray(offset),
    () => new Error("not enough buffer"), // TODO
  );
  offset += versionLength;

  if (version !== RelayVersion7) {
    // TODO: log fail
    throw new Error("fail"); // TODO: Error
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

  if (authResult !== RelayAuthentication.BASIC_AUTH) {
    // TODO: log fail
    throw new Error("fail"); // TODO: Error
  }

  const [salt, saltLength] = safeReadWithLength8(
    challenge.subarray(offset),
    () => new Error("Error"), // TODO: Error
  );
  offset += saltLength;

  const [handshakeIV, handshakeIVLength] = safeReadWithLength8(
    challenge.subarray(offset),
    () => new Error("errors"), // TODO: Error
  );
  offset += handshakeIVLength;

  const [cipheredSessionKey, cipheredSessionKeyLength] = safeReadWithLength8(
    challenge.subarray(offset),
    () => new Error("errors"), // TODO: Error
  );
  offset += cipheredSessionKeyLength;

  const hash = new Uint8Array(
    await pbkdf2Hash512(
      encoder.encode(auth.passkey),
      salt,
    ),
  );

  const handshakeKey = await crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const sessionKey = await crypto.subtle.importKey(
    "raw",
    await crypto.subtle.decrypt(
      { name: "AES-GCM", length: 256, iv: handshakeIV },
      handshakeKey,
      cipheredSessionKey,
    ),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const security = createTunnelSecurity("client", sessionKey);

  socket.send(
    await security.encrypt(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.BASIC_AUTH,
        hash.length,
        ...hash,
      ]),
    ),
  );

  return security;
}
