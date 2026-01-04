export async function generateECDHKeyPair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

export function bufferToPem(
  buffer: Uint8Array<ArrayBuffer>,
  format: "spki" | "pkcs8",
): string {
  const keyType = format === "spki" ? "PUBLIC" : "PRIVATE";
  const pemBlocks = buffer.toBase64().match(/.{1,64}/g)?.join("\n") || "";

  return `-----BEGIN ${keyType} KEY-----\n${pemBlocks}\n-----END ${keyType} KEY-----`;
}

export function pemToBuffer(
  pem: string,
): { buffer: Uint8Array<ArrayBuffer>; format: "spki" | "pkcs8" } | null {
  const result =
    /-----BEGIN (PUBLIC|PRIVATE) KEY-----([\s\S]*)-----END (PUBLIC|PRIVATE) KEY-----/
      .exec(pem);
  if (!result) return null;

  const format = result[1] === "PUBLIC" ? "spki" : "pkcs8";
  const buffer = Uint8Array.fromBase64(result[2].replaceAll(/\s+/g, ""));

  return { format, buffer };
}

export async function exportECDHKeyPair(keyPair?: CryptoKeyPair) {
  if (!keyPair) keyPair = await generateECDHKeyPair();

  const privateKeyContent = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  );
  const publicKeyContent = new Uint8Array(
    await crypto.subtle.exportKey("spki", keyPair.publicKey),
  );

  return {
    privateKey: {
      key: keyPair.privateKey,

      format: "pkcs8",
      content: {
        decoded: privateKeyContent,
        encoded: bufferToPem(privateKeyContent, "pkcs8"),
      },
    },
    publicKey: {
      key: keyPair.publicKey,

      format: "spki",
      content: {
        decoded: publicKeyContent,
        encoded: bufferToPem(publicKeyContent, "spki"),
      },
    },
  };
}

export async function importECDHPrivateKey(
  content: ArrayBuffer | Uint8Array<ArrayBuffer>,
): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    content,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );

  const jwk = await crypto.subtle.exportKey("jwk", privateKey);

  // Convert to public key
  delete jwk.d;
  jwk.key_ops = [];

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );

  return { privateKey, publicKey };
}

export async function importECDHPublicKey(
  content: ArrayBuffer | Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "spki",
    content,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
}

export async function pbkdf2Hash512(
  plaintext: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    plaintext,
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 200_000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );
  return derivedBits;
}

export async function deriveRawSecret(
  localPrivateKey: CryptoKey,
  remotePublicKey: CryptoKey,
) {
  return await crypto.subtle.deriveBits(
    { name: "ECDH", public: remotePublicKey },
    localPrivateKey,
    256,
  );
}

export async function deriveSessionKey(
  rawSecret: BufferSource,
  salt: BufferSource,
  info: BufferSource,
) {
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    rawSecret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"],
  );

  return await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    ikmKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function verifyCryptoKeyPair(keyPair: CryptoKeyPair) {
  const ephimeral = await generateECDHKeyPair();

  const partA = new Uint8Array(
    await deriveRawSecret(keyPair.privateKey, ephimeral.publicKey),
  );
  const partB = new Uint8Array(
    await deriveRawSecret(ephimeral.privateKey, keyPair.publicKey),
  );

  if (partA.length !== partB.length) return false;
  for (let i = 0; i < partA.length; ++i) {
    if (partA[i] !== partB[i]) return false;
  }
  return true;
}

export async function hashPublicKey(key: CryptoKey) {
  return await crypto.subtle.digest(
    { name: "SHA-256" },
    await crypto.subtle.exportKey("spki", key),
  );
}
