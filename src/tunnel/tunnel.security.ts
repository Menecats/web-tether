import { encodeIV } from "../common/utils.ts";

export type RelaySecurity = {
  encrypt: (
    plaintext: BufferSource,
    signal?: AbortSignal,
  ) => Promise<ArrayBuffer>;
  decrypt: (
    ciphertext: BufferSource,
    signal?: AbortSignal,
  ) => Promise<ArrayBuffer>;
};

export function createSecurity(
  localRole: "client" | "server",
  key: CryptoKey,
): RelaySecurity {
  const remoteRole = localRole === "server" ? "client" : "server";
  let localCounter = 0n;
  let remoteCounter = 0n;

  return {
    decrypt: (chiphertext) =>
      crypto.subtle.decrypt(
        { name: "AES-GCM", iv: encodeIV(remoteRole, remoteCounter++) },
        key,
        chiphertext,
      ),
    encrypt: (plaintext) =>
      crypto.subtle.encrypt(
        { name: "AES-GCM", iv: encodeIV(localRole, localCounter++) },
        key,
        plaintext,
      ),
  };
}
