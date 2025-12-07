export type TunnelSecurityRole = "relay" | "client";
export type TunnelSecurityPermissions = {
  bind:
    | { enabled: false }
    | { enabled: true; allowed: (service: string) => Promise<boolean> };

  connect:
    | { enabled: false }
    | { enabled: true; allowed: (service: string) => Promise<boolean> };
};
export type TunnelSecurity = {
  readonly role: TunnelSecurityRole;
  readonly permissions: TunnelSecurityPermissions;

  encrypt(plaintext: BufferSource, signal?: AbortSignal): Promise<ArrayBuffer>;
  decrypt(ciphertext: BufferSource, signal?: AbortSignal): Promise<ArrayBuffer>;
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
  localRole: TunnelSecurityRole,
  key: CryptoKey,
  permissions: TunnelSecurityPermissions,
): TunnelSecurity {
  const remoteRole = localRole === "relay" ? "client" : "relay";

  let localCounter = 0n;
  let remoteCounter = 0n;

  return {
    role: localRole,
    permissions: permissions,

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
