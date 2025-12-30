import { Logger } from "../../../common/log.ts";
import {
  encodeWithUint8Length,
  safeReader,
} from "../../../common/safe-buffer.ts";
import {
  deriveRawSecret,
  deriveSessionKey,
  hashCryptoKey,
} from "../../../common/security.ts";
import { ConsumableAsyncQueue } from "../../../common/utils.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import {
  RelayAuthentication,
  RelayVersion7,
} from "../../common/tunnel.const.ts";
import { TunnelClientError } from "../../common/tunnel.errors.ts";
import {
  createTunnelSecurity,
  TunnelSecurity,
} from "../../common/tunnel.security.ts";

export type HandleClientAdvancedAuthenticationOptions = {
  socket: WebSocket;
  queue: ConsumableAsyncQueue<ArrayBuffer>;
  auth: TunnelRelayClientOptions["auth"] & { mode: "advanced" };
  log: Logger;
};
export async function handleClientAdvancedAuthentication(
  { socket, queue, auth, log }: HandleClientAdvancedAuthenticationOptions,
): Promise<TunnelSecurity<"client">> {
  log.debug(`initializing`);

  log.trace(`hashing client key`);
  const clientKeyHash = await hashCryptoKey(auth.clientKeys.publicKey);

  log.trace(`sending handshake`);
  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.ADVANCED_AUTH,
      ...encodeWithUint8Length(clientKeyHash),
    ]),
  );

  log.trace(`creating session info`);
  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);

  log.trace(`deriving shared secret`);
  const sharedSecret = await deriveRawSecret(
    auth.clientKeys.privateKey,
    auth.serverKey,
  );

  log.trace(`waiting for challenge`);
  const authChallenge = safeReader(
    await queue.shift({
      timeout: 1000,
      timeoutError: () => new TunnelClientError({ reason: "timeout" }),
    }),
    () => new TunnelClientError({ reason: "buffer-too-short" }),
  );
  log.trace(`parsing received challenge`);

  const challengeVersion = authChallenge.uint8();
  if (challengeVersion !== RelayVersion7) {
    throw new TunnelClientError({
      reason: "unknown-version",
      version: challengeVersion,
    });
  }

  const challengeAuthMode = authChallenge.uint8();
  if (challengeAuthMode !== RelayAuthentication.ADVANCED_AUTH) {
    throw new TunnelClientError({
      reason: "auth-mode-unexpected",
      expectedAuth: RelayAuthentication.ADVANCED_AUTH,
      receivedAuth: challengeAuthMode,
    });
  }

  log.trace(`reading handshake salt`);
  const sessionSalt = authChallenge.data(authChallenge.uint8());

  log.trace(`reading encrypted challenge`);
  const encryptedChallenge = authChallenge.data(authChallenge.uint8());

  log.trace(`deriving session key`);
  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  log.trace(`instantiating session security`);
  const security = createTunnelSecurity({
    role: "client",
    key: sessionKey,
    permissions: undefined,
    cryptoError: (error, action) =>
      new TunnelClientError({
        reason: "cipher-error",
        error,
        action,
      }),
  });

  log.trace(`decrypting challenge`);
  const decryptedChallenge = new Uint8Array(
    await security.decrypt(encryptedChallenge),
  );

  log.trace(`solving challenge`);
  socket.send(
    await security.encrypt(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.ADVANCED_AUTH,

        ...decryptedChallenge,
      ]),
    ),
  );

  log.trace(`waiting result`);

  const authResult = safeReader(
    await queue.shift({
      timeout: 1000,
      timeoutError: () => new TunnelClientError({ reason: "timeout" }),
    }),
    () => new TunnelClientError({ reason: "buffer-too-short" }),
  );

  const resultVersion = authResult.uint8();
  if (resultVersion !== RelayVersion7) {
    throw new TunnelClientError({
      reason: "unknown-version",
      version: resultVersion,
    });
  }

  const resultAuthMode = authResult.uint8();
  if (resultAuthMode !== RelayAuthentication.AUTHORIZED) {
    throw new TunnelClientError({
      reason: "auth-mode-unexpected",
      expectedAuth: RelayAuthentication.AUTHORIZED,
      receivedAuth: resultAuthMode,
    });
  }

  log.trace(`authenticated`);

  return security;
}
