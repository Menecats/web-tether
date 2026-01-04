import { parseArgs } from "@std/cli/parse-args";
import { promptSecret } from "@std/cli/prompt-secret";
import { pbkdf2Hash512 } from "../../common/security.ts";
import { CliCommandOptions } from "../cli.types.ts";

export async function handleGenerateCredentials({
  commandArgs,
  commandLog,
}: CliCommandOptions) {
  commandLog.trace("parsing command args");
  const { username: inputUsername, password: inputPassword } = parseArgs(
    commandArgs,
    {
      string: ["password", "username"],
      alias: {
        username: ["u"],
        password: ["p"],
      },
    },
  );

  commandLog.trace("determining (or requesting) username");
  const username = inputUsername || prompt("Username:");
  if (!username) {
    commandLog.trace("no username provided aborting");
    commandLog.error("Username must be provided to generate a user");
    return;
  }

  commandLog.trace("testing for username characters validity");
  if (!/^[a-zA-Z0-9.\-_]+$/.test(username)) {
    commandLog.error(
      "Username name can only contains letters, numbers and these characters: `.`, `-` and `_`",
    );
    return;
  }

  commandLog.trace("determining (or requesting) password");
  const password = inputPassword ?? promptSecret("Password:");
  if (!password) {
    commandLog.trace("no password provided aborting");
    commandLog.error("Password must be provided to generate a user");
    return;
  }

  commandLog.trace("generating random salt");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  commandLog.debug("random salt generated:", salt);

  commandLog.trace("encoding password");
  const encodedPassword = new TextEncoder().encode(password);

  commandLog.trace("hashing password with salt");
  const hashedPassword = new Uint8Array(
    await pbkdf2Hash512(encodedPassword, salt),
  );

  commandLog.trace("printing newly generated user");
  console.log(
    `credentials:${username}:${salt.toBase64()}|${hashedPassword.toBase64()}`,
  );
}
