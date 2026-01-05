import { colorizeOutput, createLogger } from "../common/log.ts";
import { areBuffersEqual } from "../common/safe-buffer.ts";
import { pbkdf2Hash512 } from "../common/security.ts";
import { client, clientHash, server } from "../common/test-keys.ts";
import { TunnelServerError } from "../tunnel/common/tunnel.errors.ts";
import { TunnelSecurityPermissions } from "../tunnel/common/tunnel.security.ts";
import { createTunnelRelayServer } from "../tunnel/server/tunnel.server.ts";

const controller = new AbortController();

Deno.addSignalListener("SIGINT", () => {
  console.log("interrupt");
  controller.abort(new TunnelServerError({ reason: "application-aborted" }));
});

const testSalt = new Uint8Array([
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
]);
const testHash = new Uint8Array(
  await pbkdf2Hash512(new TextEncoder().encode("test"), testSalt),
);

const testPermissions = {
  bind: { enabled: true, allowed: () => Promise.resolve(true) },
  connect: { enabled: true, allowed: () => Promise.resolve(true) },
} satisfies TunnelSecurityPermissions;

await createTunnelRelayServer({
  listen: { hostname: "0.0.0.0", port: 3456 },
  performance: { decryptQueueSize: 1024 },
  auth: {
    credentials: {
      enabled: true,
      lookup: (identifier) => {
        return identifier === "test"
          ? Promise.resolve({
            salt: testSalt,
            hash: testHash,
            permissions: testPermissions,
          })
          : Promise.resolve(undefined);
      },
    },
    identity: {
      enabled: true,
      serverKeys: server,
      lookupClient: async (hash) => {
        if (areBuffersEqual(hash, clientHash)) {
          return {
            key: client.publicKey,
            permissions: {
              bind: {
                enabled: true,
                allowed: () => Promise.resolve(true),
              },
              connect: {
                enabled: true,
                allowed: () => Promise.resolve(true),
              },
            },
          };
        }

        return undefined;
      },
    },
  },
  log: createLogger(colorizeOutput(console.log)),
  signal: controller.signal,
});
