import { safeReadWithLength16 } from "../../../common/safe-buffer.ts";
import {
  deriveRawSecret,
  deriveSessionKey,
  hashCryptoKey,
} from "../../../common/security.ts";
import { randomWait } from "../../../common/utils.ts";
import { RelayAuthentication, RelayVersion7 } from "../../tunnel.const.ts";
import type { RelayHandler, RelayPacket } from "../../tunnel.relay.ts";
import { createTunnelSecurity, noPermissions } from "../../tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "../../tunnel.server.ts";

export async function* handleAdvencedAuthenticationServer(
  auth: CreateTunnelRelayOptions["auth"]["advanced"] & { enabled: true },
  socket: WebSocket,
  { buffer }: RelayPacket,
): RelayHandler {
  const [rawClientKey] = safeReadWithLength16(
    buffer,
    () => new Error("not enough buffer"), // TODO: Error
  );

  const clientKey = await crypto.subtle.importKey(
    "raw",
    rawClientKey,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
  const clientKeyHash = new Uint8Array(await hashCryptoKey(clientKey));

  const sessionSalt = crypto.getRandomValues(new Uint8Array(16));
  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);
  const sessionChallenge = crypto.getRandomValues(new Uint8Array(16));

  const clientPermissions = await auth.validateClientPublicKey(clientKeyHash);
  if (!clientPermissions) {
    // Fake authentication to prevent key identification

    const mockSharedSecret = crypto.getRandomValues(new Uint8Array(256));
    await randomWait(50, 100);

    const mockSessionKey = await deriveSessionKey(
      mockSharedSecret,
      sessionSalt,
      sessionInfo,
    );

    const mockSecurity = createTunnelSecurity(
      "relay",
      mockSessionKey,
      noPermissions(),
    );

    const mockEncryptedChallenge = new Uint8Array(
      await mockSecurity.encrypt(sessionChallenge),
    );

    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.ADVANCED_AUTH,

        sessionSalt.length,
        ...sessionSalt,

        mockEncryptedChallenge.length,
        ...mockEncryptedChallenge,
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

  const sharedSecret = await deriveRawSecret(
    auth.serverKeys.privateKey,
    clientKey,
  );
  await randomWait(50, 100);

  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  const security = createTunnelSecurity("relay", sessionKey, clientPermissions);

  const encryptedChallenge = new Uint8Array(
    await security.encrypt(sessionChallenge),
  );

  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.ADVANCED_AUTH,

      sessionSalt.length,
      ...sessionSalt,

      encryptedChallenge.length,
      ...encryptedChallenge,
    ]),
  );

  const encryptedResponse = yield { timeout: 1000 };
  await randomWait(100, 500);

  try {
    const decryptedResponse = new Uint8Array(
      await security.decrypt(encryptedResponse.buffer),
    );

    if (
      decryptedResponse[0] !== RelayVersion7 ||
      decryptedResponse[1] !== RelayAuthentication.ADVANCED_AUTH ||
      decryptedResponse.length < 2 + sessionChallenge.length
    ) {
      throw "invalid";
    }

    let invalid = false;
    for (let i = 0; i < sessionChallenge.length; ++i) {
      // Check that challenge matches
      if (sessionChallenge[i] !== decryptedResponse[2 + i]) invalid = true;
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
