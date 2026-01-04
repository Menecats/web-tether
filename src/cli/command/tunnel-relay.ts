import { z } from "zod";
import { hashPublicKey, importECDHPublicKey } from "../../common/security.ts";

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
