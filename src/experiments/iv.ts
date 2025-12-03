import { encodeIV } from "../utils.ts";

console.log("server");
console.log("0x" + encodeIV("server", 1n).toHex());
console.log("0x" + encodeIV("server", 2n).toHex());
console.log("0x" + encodeIV("server", 3n).toHex());
console.log("0x" + encodeIV("server", (2n ** 88n) + 4n).toHex());

console.log("client");
console.log("0x" + encodeIV("client", 1n).toHex());
console.log("0x" + encodeIV("client", 2n).toHex());
console.log("0x" + encodeIV("client", 3n).toHex());
console.log("0x" + encodeIV("client", (2n << 88n) + 4n).toHex());
