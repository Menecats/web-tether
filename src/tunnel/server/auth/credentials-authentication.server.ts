import { Logger } from "../../../common/log.ts";
import { SafeReader, safeReader } from "../../../common/safe-buffer.ts";
import { pbkdf2Hash512 } from "../../../common/security.ts";
import {
  concatBuffers,
  ConsumableAsyncQueue,
  randomWait,
} from "../../../common/utils.ts";
import {
  RelayAuthentication,
  RelayVersion7,
} from "../../common/tunnel.const.ts";
import { TunnelServerError } from "../../common/tunnel.errors.ts";
import {
  createTunnelSecurity,
  TunnelSecurity,
} from "../../common/tunnel.security.ts";
import type { CreateTunnelRelayOptions } from "../tunnel.server.ts";

const instanceMockSalt = crypto.getRandomValues(new Uint8Array(16));

export async function handleCredentialsAuthenticationServer(
  socket: WebSocket,
  queue: ConsumableAsyncQueue<ArrayBuffer>,
  auth: CreateTunnelRelayOptions["auth"]["credentials"] & { enabled: true },
  buffer: SafeReader,
  log: Logger,
): Promise<TunnelSecurity<"relay">> {
  const decoder = new TextDecoder();

  log.debug("reading client identifier.");
  const identifier = buffer.data(buffer.uint8());
  const decodedIdentifier = decoder.decode(identifier);

  log.debug(`looking up client '${decodedIdentifier}'.`);
  const client = await auth.lookup(decodedIdentifier);
  if (!client) {
    log.debug(
      "client not found, proceeding with mock authentication to avoid user enumeration.",
    );

    const mockSalt = new Uint8Array(
      await crypto.subtle.digest(
        { name: "SHA-256" },
        concatBuffers(instanceMockSalt, identifier),
      ),
    ).subarray(0, 16);
    const mockIV = crypto.getRandomValues(new Uint8Array(16));
    const mockKey = crypto.getRandomValues(new Uint8Array(32));

    log.debug("sending mock challenge.");
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

    log.debug("wait for pointless solution.");
    await queue.shift({
      timeout: 1000, // TODO
      timeoutError: () => new TunnelServerError({ reason: "timeout" }),
    });
    await randomWait(100, 500);

    log.info("socket unauthorized (unknown client identifier).");
    socket.send(
      new Uint8Array([RelayVersion7, RelayAuthentication.UNAUTHORIZED]),
    );
    throw new TunnelServerError({ reason: "auth-unknown-client" });
  }

  log.debug("client found, derive handshake key.");

  const handshakeIV = crypto.getRandomValues(new Uint8Array(16));
  const handshakeKey = await crypto.subtle.importKey(
    "raw",
    client.hash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  log.debug("generate and cipher session key.");
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

  log.debug("sending session challenge.");
  socket.send(
    new Uint8Array([
      RelayVersion7,
      RelayAuthentication.BASIC_AUTH,

      client.salt.length,
      ...client.salt,

      handshakeIV.length,
      ...handshakeIV,

      cipheredSessionKey.length,
      ...cipheredSessionKey,
    ]),
  );

  log.debug("wait for challenge solution.");
  const encryptedSolution = await queue.shift({
    timeout: 1000, // TODO
    timeoutError: () => new TunnelServerError({ reason: "timeout" }),
  });
  await randomWait(100, 500);

  log.debug("create tunnel security manager.");
  const security = createTunnelSecurity({
    alias: client.alias,
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

  try {
    log.debug("decrypting and validating received solution.");
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
    if (solutionAuthMode !== RelayAuthentication.BASIC_AUTH) {
      throw new TunnelServerError({
        reason: "auth-mode-unexpected",
        receivedAuth: solutionAuthMode,
        expectedAuth: RelayAuthentication.BASIC_AUTH,
      });
    }

    const challengeSolution = solution.data(solution.uint8());
    const hashedSolution = new Uint8Array(
      await pbkdf2Hash512(challengeSolution, client.salt),
    );

    if (hashedSolution.length !== client.hash.length) {
      for (let i = 0; i < client.hash.length; ++i) {
        if (client.hash[i] === hashedSolution[i]) continue;

        throw new TunnelServerError({ reason: "auth-challenge-failed" });
      }
    }

    log.info("socket authenticated.");
    socket.send(
      new Uint8Array([RelayVersion7, RelayAuthentication.AUTHORIZED]),
    );
    return security;
  } catch (error) {
    log.info("socket unauthorized (challenge failed).");
    socket.send(
      new Uint8Array([RelayVersion7, RelayAuthentication.UNAUTHORIZED]),
    );
    throw error;
  }
}
