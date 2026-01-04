import { parseArgs } from "@std/cli/parse-args";
import { promptSecret } from "@std/cli/prompt-secret";
import { pbkdf2Hash512 } from "../../common/security.ts";
import { CliCommandOptions } from "../cli.types.ts";

export async function handleGenerateCredentials({
  commandArgs,
  commandLog,
}: CliCommandOptions) {
  commandLog.trace("parsing command args");
  const { identifier: inputIdentifier, passkey: inputPasskey } = parseArgs(
    commandArgs,
    {
      string: ["passkey", "identifier"],
      alias: {
        identifier: ["i", "username", "user"],
        passkey: ["p", "pass-key", "password", "pass"],
      },
    },
  );

  commandLog.trace("determining (or requesting) identifier");
  const identifier = inputIdentifier || prompt("Identifier:");
  if (!identifier) {
    commandLog.trace("no identifier provided aborting");
    commandLog.error("Identifier must be provided to generate credentials");
    return;
  }

  commandLog.trace("testing for identifier characters validity");
  if (!/^[a-zA-Z0-9.\-_]+$/.test(identifier)) {
    commandLog.error(
      "Identifier name can only contains letters, numbers and these characters: `.`, `-` and `_`",
    );
    return;
  }

  commandLog.trace("determining (or requesting) passkey");
  const passkey = inputPasskey ?? promptSecret("Passkey:");
  if (!passkey) {
    commandLog.trace("no passkey provided aborting");
    commandLog.error("Passkey must be provided to generate a user");
    return;
  }

  commandLog.trace("generating random salt");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  commandLog.debug("random salt generated:", salt);

  commandLog.trace("encoding passkey");
  const encodedPasskey = new TextEncoder().encode(passkey);

  commandLog.trace("hashing passkey with salt");
  const hashedPasskey = new Uint8Array(
    await pbkdf2Hash512(encodedPasskey, salt),
  );

  commandLog.trace("printing newly generated credentials");
  console.log(
    `credentials:${identifier}:${salt.toBase64()}|${hashedPasskey.toBase64()}`,
  );
}
