import { Logger } from "../../../common/log.ts";
import { safeReader } from "../../../common/safe-buffer.ts";
import { pbkdf2Hash512 } from "../../../common/security.ts";
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

export type HandleClientCredentialsAuthenticationOptions = {
  socket: WebSocket;
  queue: ConsumableAsyncQueue<ArrayBuffer>;
  auth: TunnelRelayClientOptions["auth"] & { mode: "credentials" };
  log: Logger;
};
export async function handleClientCredentialsAuthentication(
  { socket, queue, auth, log }: HandleClientCredentialsAuthenticationOptions,
): Promise<TunnelSecurity<"client">> {
  log.debug(`initializing`);

  const encoder = new TextEncoder();

  const encodedIdentifier = encoder.encode(auth.identifier);

  log.trace(`sending handshake`);
  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.BASIC_AUTH,

      encodedIdentifier.length,
      ...encodedIdentifier,
    ]),
  );

  log.trace(`waiting for challenge`);
  const authChallenge = safeReader(
    await queue.shift({
      timeout: 1000, // TODO: Timeout
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
  if (challengeAuthMode !== RelayAuthentication.BASIC_AUTH) {
    throw new TunnelClientError({
      reason: "auth-mode-unexpected",
      expectedAuth: RelayAuthentication.BASIC_AUTH,
      receivedAuth: challengeAuthMode,
    });
  }

  log.trace(`reading handshake salt`);
  const salt = authChallenge.data(authChallenge.uint8());

  log.trace(`reading handshake iv`);
  const handshakeIV = authChallenge.data(authChallenge.uint8());

  log.trace(`reading chiphered session key`);
  const cipheredSessionKey = authChallenge.data(authChallenge.uint8());

  log.trace(`deriving shared hash`);
  const hash = new Uint8Array(
    await pbkdf2Hash512(
      encoder.encode(auth.passkey),
      salt,
    ),
  );

  log.trace(`deriving decryption key`);
  const handshakeKey = await crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  log.trace(`decrypting session key`);
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

  log.trace(`solving challenge`);
  socket.send(
    await security.encrypt(
      new Uint8Array([
        RelayVersion7,
        RelayAuthentication.BASIC_AUTH,
        ...hash,
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
