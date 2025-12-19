async function generateECDHKeyPair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
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

export async function hashCryptoKey(key: CryptoKey) {
  return await crypto.subtle.digest(
    { name: "SHA-256" },
    await crypto.subtle.exportKey("raw", key),
  );
}
