async function generateECDHKeyPair() {
  return await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

async function deriveSecretRaw(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey,
) {
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256,
  );
  return bits;
}

async function deriveSessionAESKeyFromSecret(
  secretRaw: Uint8Array<ArrayBuffer> | ArrayBuffer,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
) {
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    secretRaw,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"],
  );

  const hkdfSalt = salt; // deve essere lo stesso inviato dal mittente
  const hkdfInfo = info;

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: hkdfSalt,
      info: hkdfInfo,
    },
    ikmKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  return aesKey;
}

async function aesGcmEncrypt(
  aesKey: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
) {
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    plaintext,
  );
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(
  aesKey: CryptoKey,
  iv: Uint8Array<ArrayBuffer>,
  chiphertext: Uint8Array<ArrayBuffer>,
) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    chiphertext,
  );
  return new Uint8Array(pt);
}

async function exportKey(key: CryptoKey) {
  return await crypto.subtle.exportKey("jwk", key);
}

async function importKey(jwk: JsonWebKey, isPrivate: boolean) {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    isPrivate ? ["deriveKey", "deriveBits"] : [],
  );
}

const keyPairA = await generateECDHKeyPair();
const keyPairB = await generateECDHKeyPair();

const exportedPublicA = await exportKey(keyPairA.publicKey);
const exportedPrivateA = await exportKey(keyPairA.privateKey);
const exportedPublicB = await exportKey(keyPairB.publicKey);
const exportedPrivateB = await exportKey(keyPairB.privateKey);

const publicA = await importKey(exportedPublicA, false);
const privateA = await importKey(exportedPrivateA, true);
const publicB = await importKey(exportedPublicB, false);
const privateB = await importKey(exportedPrivateB, true);

const secretA = await deriveSecretRaw(privateA, publicB);
const secretB = await deriveSecretRaw(privateB, publicA);

Deno.bench({
  name: "Secret derivation",
  fn: async () => {
    await deriveSecretRaw(privateA, publicB);
  },
  warmup: 100,
  n: 100000,
});

const hkdfSalt = crypto.getRandomValues(new Uint8Array(16));
const hkdfInfo = new Uint8Array([]);

const keyA = await deriveSessionAESKeyFromSecret(secretA, hkdfSalt, hkdfInfo);
const keyB = await deriveSessionAESKeyFromSecret(secretB, hkdfSalt, hkdfInfo);

const enc = new TextEncoder();
const dec = new TextDecoder();

const ivA = new Uint8Array(12);
ivA[0] = 1;

const ivB = new Uint8Array(12);
ivB[0] = 2;

const plaintext = enc.encode("secret text");

const ciphertextA = await aesGcmEncrypt(keyA, ivA, plaintext);
const ciphertextB = await aesGcmEncrypt(keyB, ivB, plaintext);

const plaintextA = dec.decode(await aesGcmDecrypt(keyA, ivB, ciphertextB));
const plaintextB = dec.decode(await aesGcmDecrypt(keyB, ivA, ciphertextA));

console.log("plaintextA", plaintextA);
console.log("plaintextB", plaintextB);
