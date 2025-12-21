import {
  hashCryptoKey,
  importPrivateKey,
  importPublicKey,
} from "./security.ts";

const jwkServerPrivate =
  `{"kty": "EC","alg": "ECDH","crv": "P-256","x": "vvoPLvhyBgAK5MD0HqaPfHn5rloJ6dvHwjtHwZRUTww","y": "mue5yATxG-iVnHsiNC3m0D_BfQhnkdTz3aBLJe8KgEY","d": "o26lWZznPtkWTukiGIF-wXPMm76gRKxtmSqudgb3C48","key_ops": ["deriveKey", "deriveBits"],"ext": true}`;
const jwkServerPublic =
  `{"kty": "EC","alg": "ECDH","crv": "P-256","x": "vvoPLvhyBgAK5MD0HqaPfHn5rloJ6dvHwjtHwZRUTww","y": "mue5yATxG-iVnHsiNC3m0D_BfQhnkdTz3aBLJe8KgEY","key_ops": [],"ext": true}`;

const jwkClientPrivate =
  `{"kty": "EC","alg": "ECDH","crv": "P-256","x": "oGr4JTa1gJhw-EWK7RPHlmtrQ-9ydfdsRgsxJeck9h0","y": "4OvnAZuBcWN7yfcqXDlJFGHstBI3mXgk7rOPihPwrZY","d": "MUfvHh2dzc_g4NJB3sk2pktz2lOskKVGolX2htFT_7o","key_ops": ["deriveKey", "deriveBits"],"ext": true}`;
const jwkClientPublic =
  `{"kty": "EC","alg": "ECDH","crv": "P-256","x": "oGr4JTa1gJhw-EWK7RPHlmtrQ-9ydfdsRgsxJeck9h0","y": "4OvnAZuBcWN7yfcqXDlJFGHstBI3mXgk7rOPihPwrZY","key_ops": [],"ext": true}`;

export const server: CryptoKeyPair = {
  privateKey: await importPrivateKey(JSON.parse(jwkServerPrivate)),
  publicKey: await importPublicKey(JSON.parse(jwkServerPublic)),
};
export const serverHash = new Uint8Array(await hashCryptoKey(server.publicKey));

export const client: CryptoKeyPair = {
  privateKey: await importPrivateKey(JSON.parse(jwkClientPrivate)),
  publicKey: await importPublicKey(JSON.parse(jwkClientPublic)),
};
export const clientHash = new Uint8Array(await hashCryptoKey(client.publicKey));
