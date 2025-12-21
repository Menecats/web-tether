import { generateECDHKeyPair } from "../common/security.ts";

const pair = await generateECDHKeyPair();

console.log(
  "private",
  JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey)),
);
console.log(
  "public ",
  JSON.stringify(await crypto.subtle.exportKey("jwk", pair.publicKey)),
);
