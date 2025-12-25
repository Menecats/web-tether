import { Logger } from "../../../common/log.ts";
import { SafeReader, safeReader } from "../../../common/safe-buffer.ts";
import { deriveRawSecret, deriveSessionKey } from "../../../common/security.ts";
import { ConsumableAsyncQueue, randomWait } from "../../../common/utils.ts";
import { RelayAuthentication, RelayVersion7 } from "../../tunnel.const.ts";
import { TunnelServerError } from "../../tunnel.errors.ts";
import {
  createTunnelSecurity,
  noPermissions,
  TunnelSecurity,
} from "../../tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "../../tunnel.server.ts";

export async function handleAdvencedAuthenticationServer(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayOptions["auth"]["advanced"] & { enabled: true },
  buffer: SafeReader,
  log: Logger,
): Promise<TunnelSecurity<"relay">> {
  log.trace("reading client key hash.");
  const clientKeyHash = buffer.data(buffer.uint8());

  log.trace("generating session salt, info and challenge.");
  const sessionSalt = crypto.getRandomValues(new Uint8Array(16));
  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);
  const sessionChallenge = crypto.getRandomValues(new Uint8Array(16));

  log.trace(`looking up client '${clientKeyHash.toBase64()}'`);
  const client = await auth.lookupClient(clientKeyHash);
  if (!client) {
    log.trace(
      "client not found, proceeding with mock authentication to avoid user enumeration.",
    );

    const mockSharedSecret = crypto.getRandomValues(new Uint8Array(256));
    await randomWait(50, 100);

    const mockSessionKey = await deriveSessionKey(
      mockSharedSecret,
      sessionSalt,
      sessionInfo,
    );

    const mockSecurity = createTunnelSecurity({
      role: "relay",
      key: mockSessionKey,
      permissions: noPermissions(),
      cryptoError: (error, action) =>
        new TunnelServerError({
          reason: "cipher-error",
          error,
          action,
        }),
    });

    const mockEncryptedChallenge = new Uint8Array(
      await mockSecurity.encrypt(sessionChallenge),
    );

    log.trace("sending mock challenge.");
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

    log.trace("wait for pointless solution.");
    await queue.shift({
      timeout: 1000,
      timeoutError: () => new TunnelServerError({ reason: "timeout" }),
    });
    await randomWait(100, 500);

    log.debug("socket unauthorized (unknown client key hash).");
    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.UNAUTHORIZED,
      ]),
    );
    throw new TunnelServerError({ reason: "auth-unknown-client" });
  }

  log.trace("client found, derive shared secret.");

  const sharedSecret = await deriveRawSecret(
    auth.serverKeys.privateKey,
    client.key,
  );
  await randomWait(50, 100);

  log.trace("derive session key.");

  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  log.trace("create tunnel security manager.");

  const security = createTunnelSecurity({
    role: "relay",
    key: sessionKey,
    permissions: client.permissions,
    cryptoError: (error, action) =>
      new TunnelServerError({
        reason: "cipher-error",
        error,
        action,
      }),
  });

  log.trace("encrypting session challenge.");

  const encryptedChallenge = new Uint8Array(
    await security.encrypt(sessionChallenge),
  );

  log.trace("sending session challenge.");
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

  log.trace("waiting for challenge solution.");
  const encryptedSolution = await queue.shift({
    timeout: 1000, // TODO
    timeoutError: () => new TunnelServerError({ reason: "timeout" }),
  });
  await randomWait(100, 500);

  try {
    log.trace("decrypting and validating received solution.");
    const solution = safeReader(
      await security.decrypt(encryptedSolution),
      () => new TunnelServerError({ reason: "buffer-too-short" }),
    );

    const solutionVersion = solution.uint8();
    if (solutionVersion !== RelayVersion7) {
      throw new TunnelServerError({
        reason: "unknown-version",
        version: solutionVersion,
      });
    }

    const solutionAuthMode = solution.uint8();
    if (solutionAuthMode !== RelayAuthentication.ADVANCED_AUTH) {
      throw new TunnelServerError({
        reason: "auth-mode-unexpected",
        receivedAuth: solutionAuthMode,
        expectedAuth: RelayAuthentication.ADVANCED_AUTH,
      });
    }

    const challengeSolution = solution.data(sessionChallenge.length);
    for (let i = 0; i < sessionChallenge.length; ++i) {
      if (sessionChallenge[i] === challengeSolution[i]) continue;

      throw new TunnelServerError({ reason: "auth-challenge-failed" });
    }

    log.debug("socket authenticated.");
    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.AUTHORIZED,
      ]),
    );
    return security;
  } catch (error) {
    log.debug("socket unauthorized (challenge failed).");
    socket.send(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.UNAUTHORIZED,
      ]),
    );
    throw error;
  }
}
