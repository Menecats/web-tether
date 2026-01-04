import { parseArgs } from "@std/cli";
import {
  colorizeOutput,
  createLogger,
  Logger,
  LogLevel,
  LogLevels,
} from "../common/log.ts";
import { handleGenerateCredentials } from "./command/generate-credentials.ts";
import { handleGenerateIdentity } from "./command/generate-identity.ts";
import { handleTunnelConnect } from "./command/tunnel-connect.ts";
import { handleTunnelRelay } from "./command/tunnel-relay.ts";

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

function printHelp() {
  // TODO: Add help text
  console.error(`Help Text HERE`);
}

const command = Deno.args[0];
const commandArgs = Deno.args.slice(1);

const { log: logLevel } = parseArgs(commandArgs, {
  string: ["log"],
});
const commandLog = configureLogger(logLevel, console.error);

if (!command) {
  commandLog.error(`invalid args provided`);
  printHelp();
  Deno.exit(1);
}

commandLog.trace(`handling command '${command}'`);
switch (command) {
  case "generate-credentials":
    await handleGenerateCredentials({ command, commandArgs, commandLog });
    Deno.exit(0);
    break;

  case "generate-identity":
    await handleGenerateIdentity({ command, commandArgs, commandLog });
    Deno.exit(0);
    break;

  case "relay":
    await handleTunnelRelay({ command, commandArgs, commandLog });
    Deno.exit(0);
    break;

  case "connect":
    await handleTunnelConnect({ command, commandArgs, commandLog });
    Deno.exit(0);
    break;

  default:
    commandLog.error(`unknown command '${command}'`);
    printHelp();
    Deno.exit(1);
}
