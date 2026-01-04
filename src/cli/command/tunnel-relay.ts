import { parseArgs } from "@std/cli/parse-args";
import { parse } from "@std/yaml";
import { isIPv4 } from "node:net";
import { z } from "zod";
import { asyncAction } from "../../common/async.ts";
import { safeStat } from "../../common/fs.ts";
import { prefixLogger } from "../../common/log.ts";
import { areBuffersEqual } from "../../common/safe-buffer.ts";
import {
  hashPublicKey,
  importECDHPrivateKey,
  importECDHPublicKey,
  pemToBuffer,
} from "../../common/security.ts";
import { TunnelServerError } from "../../tunnel/common/tunnel.errors.ts";
import { TunnelSecurityPermissions } from "../../tunnel/common/tunnel.security.ts";
import { createTunnelRelayServer } from "../../tunnel/server/tunnel.server.ts";
import { CliCommandOptions } from "../cli.types.ts";

function patternToRegExp(pattern: string): RegExp {
  return new RegExp(`^${
    pattern
      .replace(/([^*]+|\*+)/g, (a) => {
        return a.includes("*") ? ".*" : RegExp.escape(a);
      })
  }$`);
}

export const TunnelRelayPermissionsSchema = z.object({
  version: z.literal(1),
  clients: z.array(z.object({
    alias: z.string(),
    auth: z.union([
      z.discriminatedUnion("mode", [
        z.object({
          mode: z.literal("credentials"),
          identifier: z.string(),
          credentials: z.string(),
        }),
        z.object({
          mode: z.literal("identity"),
          publicKey: z.string(),
        }),
      ]),
      z.string().transform((input, ctx) => {
        const definition = input.split(":");
        const mode = definition[0].trim();

        if (mode === "credentials") {
          if (definition.length !== 3) {
            ctx.issues.push({
              code: "custom",
              message:
                "Invalid 'credentials' auth format, expected 'credentials:<identifier>:<credentials>'",
              input,
            });

            return z.NEVER;
          }
          return {
            mode,
            identifier: definition[1].trim(),
            credentials: definition[2].trim(),
          } as const;
        }
        if (mode === "identity") {
          if (definition.length !== 2) {
            ctx.issues.push({
              code: "custom",
              message:
                "Invalid 'identity' auth format, expected 'identity:<publicKey>'",
              input,
            });
            return z.NEVER;
          }

          return { mode, publicKey: definition[1].trim() } as const;
        }

        ctx.issues.push({
          code: "custom",
          message: "Unknown auth mode",
          input,
        });
        return z.NEVER;
      }),
    ]).transform(async (input, ctx) => {
      if (input.mode === "credentials") {
        const chunks = input.credentials.split("|");
        if (chunks.length !== 2) {
          ctx.issues.push({
            code: "custom",
            message: "Credentials format must be 'salt|hash'",
            input,
          });
          return z.NEVER;
        }

        let salt: Uint8Array<ArrayBuffer> | undefined;
        try {
          salt = Uint8Array.fromBase64(chunks[0].trim());
        } catch {
          ctx.issues.push({
            code: "custom",
            message: "Credentials 'salt' must be a valid base64 value",
            input,
          });
        }
        let hash: Uint8Array<ArrayBuffer> | undefined;
        try {
          hash = Uint8Array.fromBase64(chunks[1].trim());
        } catch {
          ctx.issues.push({
            code: "custom",
            message: "Credentials 'hash' must be a valid base64 value",
            input,
          });
        }

        if (!salt || !hash) return z.NEVER;

        const credentials = { salt, hash };

        return { ...input, credentials };
      }

      if (input.mode === "identity") {
        let publicKeyContent: Uint8Array<ArrayBuffer>;
        try {
          publicKeyContent = Uint8Array.fromBase64(input.publicKey);
        } catch {
          ctx.issues.push({
            code: "custom",
            message: "Not a valid base64 value",
            input,
          });
          return z.NEVER;
        }

        let publicKey: CryptoKey;
        try {
          publicKey = await importECDHPublicKey(publicKeyContent);
        } catch {
          ctx.issues.push({
            code: "custom",
            message: "Not a valid ECDH public key",
            input,
          });

          return z.NEVER;
        }

        const publicKeyHash = new Uint8Array(await hashPublicKey(publicKey));

        return { ...input, publicKey, hash: publicKeyHash };
      }

      ctx.issues.push({
        code: "custom",
        message: "Unknown auth mode",
        input,
      });
      return z.NEVER;
    }),
    permissions: z.array(z.union([
      z.object({
        type: z.enum(["bind", "connect"]),
        service: z.string(),
      }),
      z.string().transform((input, ctx) => {
        const definition = input.split("|");
        if (definition.length !== 2) {
          ctx.issues.push({
            code: "custom",
            message: "Format must be 'type|service'",
            input,
            continue: true,
          });
          return z.NEVER;
        }

        const type = z.enum(["bind", "connect"]).safeParse(
          definition[0].trim(),
        );
        if (!type.success) {
          type.error.issues.forEach((issue) => {
            ctx.issues.push({
              code: "invalid_value",
              values: ["bind", "connect"],
              message: issue.message,
              input,
              continue: true,
            });
          });
          return z.NEVER;
        }

        return { type: type.data, service: definition[1].trim() };
      }),
    ])).transform((permissions) =>
      permissions.map((permission) => {
        const regExp = patternToRegExp(permission.service);

        return {
          type: permission.type,
          pattern: permission.service,
          service: (service: string) => regExp.test(service),
        };
      })
    ),
  })),
});
export type TunnelRelayPermissionsSchema = z.infer<
  typeof TunnelRelayPermissionsSchema
>;

export async function handleTunnelRelay({
  commandArgs,
  commandLog,
}: CliCommandOptions) {
  const { identity, clients, host, port } = parseArgs(commandArgs, {
    string: ["identity", "clients", "port", "host"],
    default: {
      host: "0.0.0.0",
      port: "3456",
    },
    alias: {
      "identity": ["i"],
      "clients": ["c"],
    },
  });

  if (!isIPv4(host)) {
    commandLog.error(`specified host must be an ipv4 address`);
    return;
  }

  if (!/^\s*-?\d+\s*$/.test(port)) {
    commandLog.error(`specified port must be a number`);
    return;
  }

  const parsedPort = parseInt(port.trim());
  if (parsedPort < 1 || parsedPort > 65535) {
    commandLog.error(`specified port must be between 1 and 65535`);
    return;
  }

  let relayIdentity: CryptoKeyPair | undefined;
  if (!identity) {
    commandLog.warn(
      "[identity]",
      `Identify file not specified, clients with 'identity' authenticaiton method won't be able to connect.`,
    );
    relayIdentity = undefined;
  } else {
    commandLog.trace(
      "[identity]",
      `checking identity file existance`,
    );
    const stat = await safeStat(identity);
    if (!stat) {
      commandLog.error("[identity]", `Identity file '${identity}' not found.`);
      return;
    }

    commandLog.trace(
      "[identity]",
      `reading identity file content`,
    );
    const privateKey = await Deno.readTextFile(identity);

    commandLog.trace(
      "[identity]",
      `parsing identity from pem`,
    );
    const privateKeyBuffer = pemToBuffer(privateKey);
    if (!privateKeyBuffer) {
      commandLog.error("[identity]", `Invalid key content, not in PEM format.`);
      return;
    }
    if (privateKeyBuffer.format !== "pkcs8") {
      commandLog.error("[identity]", `Invalid key content, not a private key.`);
      return;
    }

    try {
      commandLog.trace("[identity]", `importing private key`);
      relayIdentity = await importECDHPrivateKey(privateKeyBuffer.buffer);
    } catch (err) {
      commandLog.error(
        "[identity]",
        `Error importing private key content`,
        err,
      );
      return;
    }
  }

  if (!clients) {
    commandLog.error(`Clients file must be specified '--clients <filePath>'.`);
    return;
  }

  let relayPermissions: TunnelRelayPermissionsSchema | undefined;
  async function readPermissions(): Promise<boolean> {
    const log = prefixLogger(commandLog, "[config:read]");

    log.trace("checking clients file existance");
    const stat = await safeStat(clients!);
    if (!stat) {
      relayPermissions = undefined;
      log.warn(
        `Clients file '${clients}' not found, clients won't be able to connect.`,
      );
      return false;
    }

    try {
      log.trace("reading clients file content");
      const content = await Deno.readTextFile(clients!);
      let decoded: unknown = undefined;
      try {
        log.trace("try parsing content as JSON");
        decoded = JSON.parse(content);
      } catch (err) {
        log.trace("JSON parsing failed", err);

        try {
          log.trace("try parsing content as YAML");
          decoded = parse(content);
        } catch (err) {
          log.trace("YAML parsing failed", err);
        }
      }

      if (!decoded) throw "Content is neigher JSON nor YAML";

      log.trace("parsing configuration");

      relayPermissions = await TunnelRelayPermissionsSchema.parseAsync(decoded);

      log.trace("configuration parsed successfully");
      return true;
    } catch (err) {
      log.error(
        `Error while reading clients file '${clients}', clients won't be able to connect.`,
        err,
      );
      relayPermissions = undefined;
      return false;
    }
  }

  if (!await readPermissions()) {
    commandLog.error(`Clients file '${clients}' not found.`);
    return;
  }

  const controller = new AbortController();
  asyncAction(async () => {
    const log = prefixLogger(commandLog, "[config:watch]");
    log.info("starting clients file watcher");

    const watcher = Deno.watchFs(clients);
    for await (const event of watcher) {
      if (event.kind === "access") continue;

      log.trace("clienst file changed, reading it", event);
      await readPermissions();
    }
  }, controller);

  const interruptListener = () => {
    commandLog.info("[signal]", "Interrupted");
    controller.abort(new TunnelServerError({ reason: "application-aborted" }));
  };

  Deno.addSignalListener("SIGINT", interruptListener);
  try {
    await createTunnelRelayServer({
      listen: { hostname: host, port: parsedPort },
      performance: { decryptQueueSize: 1024 },
      auth: {
        credentials: {
          enabled: true,
          lookup: (identifier) => {
            if (!relayPermissions) return undefined;

            const client = relayPermissions.clients.find((c) =>
              c.auth.mode === "credentials" && c.auth.identifier === identifier
            );
            if (!client || client.auth.mode !== "credentials") return undefined;

            return {
              salt: client.auth.credentials.salt,
              hash: client.auth.credentials.hash,
              permissions: {
                bind: !client.permissions.some((p) => p.type === "bind")
                  ? { enabled: false }
                  : {
                    enabled: true,
                    allowed: (service: string) =>
                      client.permissions.some((p) =>
                        p.type === "bind" && p.service(service)
                      ),
                  },
                connect: !client.permissions.some((p) => p.type === "connect")
                  ? { enabled: false }
                  : {
                    enabled: true,
                    allowed: (service: string) =>
                      client.permissions.some((p) =>
                        p.type === "connect" && p.service(service)
                      ),
                  },
              } satisfies TunnelSecurityPermissions,
            };
          },
        },
        identity: !relayIdentity ? { enabled: false } : {
          enabled: true,
          serverKeys: relayIdentity,
          lookupClient: (hash) => {
            if (!relayPermissions) return undefined;

            const client = relayPermissions.clients.find((c) =>
              c.auth.mode === "identity" && areBuffersEqual(hash, c.auth.hash)
            );
            if (!client || client.auth.mode !== "identity") return undefined;

            return {
              key: client.auth.publicKey,
              permissions: {
                bind: !client.permissions.some((p) => p.type === "bind")
                  ? { enabled: false }
                  : {
                    enabled: true,
                    allowed: (service: string) =>
                      client.permissions.some((p) =>
                        p.type === "bind" && p.service(service)
                      ),
                  },
                connect: !client.permissions.some((p) => p.type === "connect")
                  ? { enabled: false }
                  : {
                    enabled: true,
                    allowed: (service: string) =>
                      client.permissions.some((p) =>
                        p.type === "connect" && p.service(service)
                      ),
                  },
              } satisfies TunnelSecurityPermissions,
            };
          },
        },
      },
      log: commandLog,
      signal: controller.signal,
    });
  } finally {
    Deno.removeSignalListener("SIGINT", interruptListener);
  }
}
