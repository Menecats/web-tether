import { parseArgs, promptSecret } from "@std/cli";
import { join } from "@std/path";
import { safeStat } from "../common/fs.ts";
import {
  colorizeOutput,
  createLogger,
  Logger,
  LogLevel,
  LogLevels,
} from "../common/log.ts";
import { exportECDHKeyPair, pbkdf2Hash512 } from "../common/security.ts";

type TunnelConfig =
  & { log: Logger }
  & (
    | { type: "invalid-args" }
    | { type: "unknown-command"; command: string }
    | {
      type: "command";
      command: "generate-user";
      username: string | undefined;
      password: string | undefined;
    }
    | {
      type: "command";
      command: "generate-identity";
      identityName: string | undefined;
    }
    // TODO: Add relay and connect commands
  );

function configureLogger(
  configLevel: string | undefined,
  output: (...args: unknown[]) => void,
): Logger {
  const logLevel = configLevel && LogLevels.includes(configLevel as LogLevel)
    ? configLevel as LogLevel
    : "info";
  const valid = !configLevel || configLevel === logLevel;

  const allowedLogLevels = LogLevels.slice(LogLevels.indexOf(logLevel));

  const logger = createLogger(
    colorizeOutput(
      output,
      (level: LogLevel) => allowedLogLevels.includes(level),
    ),
  );

  if (!valid) {
    logger.warn(
      `Invalid selected log level '${configLevel}', using '${logLevel}' instead`,
    );
  }

  return logger;
}

function readTunnelConfig(inputArgs: string[]): TunnelConfig {
  if (!inputArgs.length) {
    return {
      type: "invalid-args",
      log: configureLogger(undefined, console.error),
    };
  }

  const command = inputArgs[0];
  const commandArgs = inputArgs.slice(1);

  switch (command) {
    // TODO: Handle relay command
    /*case "relay": {
      parseArgs(commandArgs, {});
      return;
    }

    // TODO: Handle connect command
    case "connect": {
      parseArgs(commandArgs, {});
      return;
    }*/

    case "generate-identity": {
      const { log, ["identity-name"]: identityName } = parseArgs(commandArgs, {
        string: ["identity-name", "log"],
        alias: {
          "identity-name": ["i"],
        },
      });

      return {
        type: "command",
        command: "generate-identity",
        log: configureLogger(log, console.error),

        identityName: identityName || undefined,
      };
    }

    case "generate-user": {
      const { username, password, log } = parseArgs(commandArgs, {
        string: ["password", "username", "log"],
        alias: {
          username: ["u"],
          password: ["p"],
        },
      });

      return {
        type: "command",
        command: "generate-user",
        log: configureLogger(log, console.error),
        username: username || undefined,
        password: password || undefined,
      };
    }

    default: {
      const { log } = parseArgs(commandArgs, {
        string: ["log"],
      });

      return {
        type: "unknown-command",
        command,
        log: configureLogger(log, console.error),
      };
    }
  }
}
function printHelp() {
  // TODO: Add help text
  console.error(`asdf`);
}

const config = readTunnelConfig(Deno.args);

if (config.type === "invalid-args") {
  config.log.error(`invalid args provided`);
  printHelp();
  Deno.exit(1);
}

if (config.type === "unknown-command") {
  config.log.error(`unknown command '${config.command}'`);
  printHelp();
  Deno.exit(1);
}

switch (config.command) {
  case "generate-user": {
    config.log.trace("determining (or requesting) username");
    const username = config.username ?? prompt("Username:");
    if (!username) {
      config.log.trace("no username provided aborting");
      config.log.error("Username must be provided to generate a user");
      break;
    }

    config.log.trace("determining (or requesting) password");
    const password = config.password ?? promptSecret("Password:");
    if (!password) {
      config.log.trace("no password provided aborting");
      config.log.error("Password must be provided to generate a user");
      break;
    }

    config.log.trace("generating random salt");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    config.log.debug("random salt generated:", salt);

    config.log.trace("encoding password");
    const encodedPassword = new TextEncoder().encode(password);

    config.log.trace("hashing password with salt");
    const hashedPassword = new Uint8Array(
      await pbkdf2Hash512(encodedPassword, salt),
    );

    config.log.trace("printing newly generated user");
    console.log(
      `"${username}": "${salt.toBase64()}|${hashedPassword.toBase64()}"`,
    );
    break;
  }

  case "generate-identity": {
    config.log.trace("generate and export key pair");
    const pair = await exportECDHKeyPair();

    config.log.trace("determining (or requesting) identity name");
    const identityName = config.identityName ?? prompt("Identity Name:");
    if (!identityName) {
      config.log.trace("no identity name provided aborting");
      config.log.error(
        "Identity name must be provided to generate an identity",
      );
      break;
    }

    if (!/^[a-z0-9.\-_ ]+$/i.test(identityName)) {
      config.log.trace("identity name contains invalid characters");
      config.log.error(
        "Identity name can only contains letters, numbers, spaces and these characters: `.`, `-` and `_`",
      );
      break;
    }

    const privateIdentityFile = join(Deno.cwd(), identityName);
    const publicIdentityFile = privateIdentityFile + ".pub";

    const privateIdentityStat = await safeStat(privateIdentityFile);
    const publicIdentityStat = await safeStat(publicIdentityFile);

    if (privateIdentityStat || publicIdentityStat) {
      config.log.trace("identity private and public files already exists");
      config.log.error(
        `Found an already existing private and/or public identity file for identity '${identityName}', please remove and try again.`,
      );
      break;
    }

    await Deno.writeTextFile(
      privateIdentityFile,
      pair.privateKey.content.encoded,
    );
    await Deno.writeTextFile(
      publicIdentityFile,
      pair.publicKey.content.decoded.toBase64(),
    );

    config.log.info(`Identity '${identityName}' successfully generated.`);
    break;
  }

  // TODO: Add relay and connect commands support

  default: {
    throw new Error(
      `Command not handled: ${JSON.stringify(JSON.stringify(config))} `,
    );
  }
}
