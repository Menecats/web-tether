import { pbkdf2Hash512 } from "../common/security.ts";

console.log(new Uint8Array(
  await pbkdf2Hash512(
    new TextEncoder().encode("password"),
    new Uint8Array(),
  ),
).toBase64());
