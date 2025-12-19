import { createLogger } from "./common/log.ts";
import { pbkdf2Hash512 } from "./common/security.ts";
import { TunnelSecurityPermissions } from "./tunnel/tunnel.security.ts";
import { createTunnelRelay } from "./tunnel/tunnel.server.ts";

const controller = new AbortController();

Deno.addSignalListener("SIGINT", () => {
  console.log("interrupt");
  controller.abort();
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
  await pbkdf2Hash512(
    new TextEncoder().encode("test"),
    testSalt,
  ),
);
const testPermissions = {
  bind: { enabled: true, allowed: () => Promise.resolve(true) },
  connect: { enabled: true, allowed: () => Promise.resolve(true) },
} satisfies TunnelSecurityPermissions;

await createTunnelRelay({
  listen: { hostname: "0.0.0.0", port: 3456 },
  auth: {
    basic: {
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
    advanced: { enabled: false },
    queueSize: 1024,
  },
  log: createLogger((level, content) => console.log(level, ...content)),
  signal: controller.signal,
});
