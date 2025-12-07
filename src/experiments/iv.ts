import { encodeIV } from "../tunnel/tunnel.security.ts";

console.log("relay");
console.log("0x" + encodeIV("relay", 1n).toHex());
console.log("0x" + encodeIV("relay", 2n).toHex());
console.log("0x" + encodeIV("relay", 3n).toHex());
console.log("0x" + encodeIV("relay", (2n ** 88n) + 4n).toHex());

console.log("client");
console.log("0x" + encodeIV("client", 1n).toHex());
console.log("0x" + encodeIV("client", 2n).toHex());
console.log("0x" + encodeIV("client", 3n).toHex());
console.log("0x" + encodeIV("client", (2n << 88n) + 4n).toHex());
