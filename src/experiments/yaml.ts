import { parse, stringify } from "@std/yaml";
import { z } from "zod";
import { TunnelRelayPermissionsSchema } from "../cli/command/tunnel-relay.ts";

const obj = {
  version: 1,
  clients: [
    {
      alias: "user-01",
      auth:
        "credentials:my-user:66SK7wXifbC+wumP8ip3PA==|O61PhhW9rW8cD7kgehyjitgGWvWjaWxkqnU3d+uKOmc=",

      permissions: ["connect|*"],
    },
    {
      alias: "ship-01",
      auth:
        "identity:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6e5YbLkOE6+QKv5c5gqohYO8eIU6XKQdx5uwO7wOV7M3EQD8VVztUmB7Tzs7nQphD+WUg8fcvv+d1iqrLur6nQ==",

      permissions: ["bind|ship-01:*"],
    },
  ],
} satisfies z.input<typeof TunnelRelayPermissionsSchema>;

const yamlEncoded = stringify(obj);
const jsonEncoded = JSON.stringify(obj, null, 2);

const decoded = await TunnelRelayPermissionsSchema.parseAsync(
  parse(yamlEncoded),
);

console.log(yamlEncoded);
console.log(jsonEncoded);
console.log(decoded);
