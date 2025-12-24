export type TunnelSecurityRole = "relay" | "client";
export type TunnelSecurityPermissions = {
  bind:
    | { enabled: false }
    | { enabled: true; allowed: (service: string) => Promise<boolean> };

  connect:
    | { enabled: false }
    | { enabled: true; allowed: (service: string) => Promise<boolean> };
};
export type TunnelSecurity<Role extends TunnelSecurityRole> = {
  readonly role: Role;
  readonly permissions: Role extends "relay" ? TunnelSecurityPermissions
    : undefined;

  encrypt(
    plaintext: ArrayBuffer | Uint8Array<ArrayBuffer>,
    signal?: AbortSignal,
  ): Promise<ArrayBuffer>;
  decrypt(
    ciphertext: ArrayBuffer | Uint8Array<ArrayBuffer>,
    signal?: AbortSignal,
  ): Promise<ArrayBuffer>;
};

export function encodeIV(role: TunnelSecurityRole, counter: bigint) {
  const iv = new Uint8Array(12);
  const view = new DataView(iv.buffer);

  counter = counter % (2n ** 88n);

  const high = counter >> 64n;
  const low = counter & (2n ** 64n - 1n);

  view.setUint32(0, Number(high));
  view.setBigUint64(4, low);

  iv[0] = role === "relay" ? 0x01 : 0x02;

  return iv;
}

export function noPermissions(): TunnelSecurityPermissions {
  return { bind: { enabled: false }, connect: { enabled: false } };
}

export type TunnelSecurityOptions<Role extends TunnelSecurityRole> = {
  role: Role;
  key: CryptoKey;
  permissions: TunnelSecurity<Role>["permissions"];
  cryptoError: (sourceError: unknown, action: "encrypt" | "decrypt") => unknown;
};

export function createTunnelSecurity<Role extends TunnelSecurityRole>(
  options: TunnelSecurityOptions<Role>,
): TunnelSecurity<Role> {
  const localRole = options.role;
  const remoteRole = options.role === "relay" ? "client" : "relay";

  let localCounter = 0n;
  let remoteCounter = 0n;

  return {
    role: localRole,
    permissions: options.permissions as TunnelSecurity<Role>["permissions"],

    decrypt: async (chiphertext) => {
      const counter = remoteCounter++;

      try {
        return await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: encodeIV(remoteRole, counter) },
          options.key,
          chiphertext,
        );
      } catch (error) {
        throw options.cryptoError(error, "decrypt");
      }
    },
    encrypt: async (plaintext) => {
      const counter = localCounter++;
      try {
        return await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: encodeIV(localRole, counter) },
          options.key,
          plaintext,
        );
      } catch (error) {
        throw options.cryptoError(error, "encrypt");
      }
    },
  };
}
