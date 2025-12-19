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
    plaintext: BufferSource,
    signal?: AbortSignal,
  ): Promise<ArrayBuffer>;
  decrypt(
    ciphertext: BufferSource,
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

export function createTunnelSecurity(
  localRole: "client",
  key: CryptoKey,
): TunnelSecurity<"client">;
export function createTunnelSecurity(
  localRole: "relay",
  key: CryptoKey,
  permissions: TunnelSecurityPermissions,
): TunnelSecurity<"relay">;
export function createTunnelSecurity<Role extends TunnelSecurityRole>(
  localRole: Role,
  key: CryptoKey,
  permissions?: TunnelSecurity<Role>["permissions"],
): TunnelSecurity<Role> {
  const remoteRole = localRole === "relay" ? "client" : "relay";

  let localCounter = 0n;
  let remoteCounter = 0n;

  return {
    role: localRole,
    permissions: permissions as TunnelSecurity<Role>["permissions"],

    decrypt(chiphertext) {
      return crypto.subtle.decrypt(
        { name: "AES-GCM", iv: encodeIV(remoteRole, remoteCounter++) },
        key,
        chiphertext,
      );
    },
    encrypt(plaintext) {
      return crypto.subtle.encrypt(
        { name: "AES-GCM", iv: encodeIV(localRole, localCounter++) },
        key,
        plaintext,
      );
    },
  };
}
