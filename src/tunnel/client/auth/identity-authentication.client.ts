import { Logger } from "../../../common/log.ts";
import {
  encodeWithUint8Length,
  safeReader,
} from "../../../common/safe-buffer.ts";
import {
  deriveRawSecret,
  deriveSessionKey,
  hashPublicKey,
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

export type HandleClientIdentityAuthenticationOptions = {
  socket: WebSocket;
  queue: ConsumableAsyncQueue<ArrayBuffer>;
  auth: TunnelRelayClientOptions["auth"] & { mode: "identity" };
  log: Logger;
};
export async function handleClientIdentityAuthentication({
  socket,
  queue,
  auth,
  log,
}: HandleClientIdentityAuthenticationOptions): Promise<
  TunnelSecurity<"client">
> {
  log.debug(`initializing`);

  log.debug(`hashing client key`);
  const clientKeyHash = await hashPublicKey(auth.clientKeys.publicKey);

  log.info(`sending handshake`);
  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.ADVANCED_AUTH,
      ...encodeWithUint8Length(clientKeyHash),
    ]),
  );

  log.debug(`creating session info`);
  const sessionInfo = new Uint8Array([
    RelayVersion7,
    RelayAuthentication.ADVANCED_AUTH,
  ]);

  log.debug(`deriving shared secret`);
  const sharedSecret = await deriveRawSecret(
    auth.clientKeys.privateKey,
    auth.serverKey,
  );

  log.info(`waiting for challenge`);
  const authChallenge = safeReader(
    await queue.shift({
      timeout: 1000,
      timeoutError: () => new TunnelClientError({ reason: "timeout" }),
    }),
    () => new TunnelClientError({ reason: "buffer-too-short" }),
  );
  log.debug(`parsing received challenge`);

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

  log.debug(`reading handshake salt`);
  const sessionSalt = authChallenge.data(authChallenge.uint8());

  log.debug(`reading encrypted challenge`);
  const encryptedChallenge = authChallenge.data(authChallenge.uint8());

  log.debug(`deriving session key`);
  const sessionKey = await deriveSessionKey(
    sharedSecret,
    sessionSalt,
    sessionInfo,
  );

  log.debug(`instantiating session security`);
  const security = createTunnelSecurity({
    alias: undefined,
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

  log.debug(`decrypting challenge`);
  const decryptedChallenge = new Uint8Array(
    await security.decrypt(encryptedChallenge),
  );

  log.info(`solving challenge`);
  socket.send(
    await security.encrypt(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.ADVANCED_AUTH,

        ...decryptedChallenge,
      ]),
    ),
  );

  log.debug(`waiting result`);

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

  log.info(`authenticated`);

  return security;
}
