import { assertEnabled, randomWait } from "../../common/utils.ts";
import { RelayAuthentication, RelayVersion7 } from "../tunnel.const.ts";
import type { RelayHandler, RelayPacket } from "../tunnel.relay.ts";
import { createSecurity } from "../tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "../tunnel.server.ts";

async function deriveRawSecret(
  localPrivateKey: CryptoKey,
  remotePublicKey: CryptoKey,
) {
  return await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    localPrivateKey,
    256,
  );
}

async function deriveSessionKey(
  rawSecret: BufferSource,
  salt: BufferSource,
  info: BufferSource,
) {
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    rawSecret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"],
  );

  return await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    ikmKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function* handleAdvencedAuthenticationMode(
  options: CreateTunnelRelayOptions,
  socket: WebSocket,
  { buffer, view }: RelayPacket,
): RelayHandler {
  assertEnabled(options.auth.advanced);

  let offset = 0;

  const identifierLength = view.getUint16(offset);
  offset += 2;

  // TODO: Check out of bound read
  const identifier = buffer.subarray(offset, offset + identifierLength);
  offset += identifierLength;

  const sessionSalt = crypto.getRandomValues(new Uint8Array(16));
  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);
  const sessionChallenge = crypto.getRandomValues(new Uint8Array(16));

  const remotePublicKey = await options.auth.advanced.lookupPublicKey(
    identifier,
  );
  if (!remotePublicKey) {
    // Fake authentication to prevent key identification

    const mockSharedSecret = crypto.getRandomValues(new Uint8Array(256));
    await randomWait(50, 100);

    const mockSessionKey = await deriveSessionKey(
      mockSharedSecret,
      sessionSalt,
      sessionInfo,
    );

    const mockSecurity = createSecurity("server", mockSessionKey);

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
    await options.auth.advanced.lookupPrivateKey(),
    remotePublicKey,
  );
  await randomWait(50, 100);

  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  const security = createSecurity("server", sessionKey);

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
      // Check that challenge is successfully reversed
      if (
        sessionChallenge[i] !==
          decryptedResponse[2 + (sessionChallenge.length - i - 1)]
      ) invalid = true;
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
