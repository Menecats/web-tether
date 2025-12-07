import {
  assertEnabled,
  concatBuffers,
  randomWait,
} from "../../common/utils.ts";
import { RelayAuthentication, RelayVersion7 } from "../tunnel.const.ts";
import type { RelayHandler, RelayPacket } from "../tunnel.relay.ts";
import { createTunnelSecurity } from "../tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "../tunnel.server.ts";

const instanceMockSalt = crypto.getRandomValues(new Uint8Array(16));

export async function* handleBasicAuthenticationMode(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
  { buffer }: RelayPacket,
): RelayHandler {
  assertEnabled(options.auth.basic);

  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  let offset = 0;

  const identifierLength = buffer[offset];
  offset += 1;

  const identifier = decoder.decode(
    // TODO: Check out of bound read
    buffer.subarray(offset, offset + identifierLength),
  );
  offset += identifierLength;

  const lookup = await options.auth.basic.lookup(identifier);
  if (!lookup) {
    // Fake authentication to prevent user identifier

    const mockSalt = new Uint8Array(
      await crypto.subtle.digest(
        { name: "MD5" },
        concatBuffers(instanceMockSalt, encoder.encode(identifier)),
      ),
    );
    const mockIV = crypto.getRandomValues(new Uint8Array(16));
    const mockKey = crypto.getRandomValues(new Uint8Array(32));

    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.BASIC_AUTH,

        mockSalt.length,
        ...mockSalt,

        mockIV.length,
        ...mockIV,

        mockKey.length,
        ...mockKey,
      ]),
    );

    yield { timeout: 1000 };
    await randomWait(100, 500);

    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.UNAUTHORIZED,
      ]),
    );
    return;
  }

  const handshakeIV = crypto.getRandomValues(new Uint8Array(16));
  const handshakeKey = await crypto.subtle.importKey(
    "raw",
    lookup.hash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const sessionKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const cipheredSessionKey = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", length: 256, iv: handshakeIV },
      handshakeKey,
      await crypto.subtle.exportKey("raw", sessionKey),
    ),
  );

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.BASIC_AUTH,

      lookup.salt.length,
      ...lookup.salt,

      handshakeIV.length,
      ...handshakeIV,

      cipheredSessionKey.length,
      ...cipheredSessionKey,
    ]),
  );

  const encryptedResponse = yield { timeout: 1000 };
  await randomWait(100, 500);

  const security = createTunnelSecurity(
    "relay",
    sessionKey,
    lookup.permissions,
  );

  try {
    const decryptedResponse = new Uint8Array(
      await security.decrypt(encryptedResponse.buffer),
    );

    if (
      decryptedResponse[0] !== RelayVersion7 ||
      decryptedResponse[1] !== RelayAuthentication.BASIC_AUTH ||
      decryptedResponse.length < 2 + lookup.hash.length
    ) {
      throw "invalid";
    }

    let invalid = false;
    for (let i = 0; i < lookup.hash.length; ++i) {
      if (lookup.hash[i] !== decryptedResponse[2 + i]) invalid = true;
    }

    if (invalid) throw "invalid";

    return security;
  } catch {
    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.UNAUTHORIZED,
      ]),
    );
    return;
  }
}
