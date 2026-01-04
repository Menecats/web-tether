import { parseArgs } from "@std/cli/parse-args";
import { join } from "@std/path/join";
import { safeStat } from "../../common/fs.ts";
import { exportECDHKeyPair } from "../../common/security.ts";
import { CliCommandOptions } from "../cli.types.ts";

export async function handleGenerateIdentity({
  commandArgs,
  commandLog,
}: CliCommandOptions) {
  commandLog.trace("parsing command args");
  const { ["identity-name"]: inputIdentityName } = parseArgs(commandArgs, {
    string: ["identity-name"],
    alias: {
      "identity-name": ["i", "identity"],
    },
  });

  commandLog.trace("generate and export key pair");
  const pair = await exportECDHKeyPair();

  commandLog.trace("determining (or requesting) identity name");
  const identityName = inputIdentityName || prompt("Identity Name:");
  if (!identityName) {
    commandLog.trace("no identity name provided aborting");
    commandLog.error(
      "Identity name must be provided to generate an identity",
    );
    return;
  }

  commandLog.trace("testing for identity name characters validity");
  if (!/^[a-zA-Z0-9.\-_]+$/.test(identityName)) {
    commandLog.error(
      "Identity name can only contains letters, numbers and these characters: `.`, `-` and `_`",
    );
    return;
  }

  commandLog.trace("testing that identity name doesn't end with '.pub'");
  if (identityName.endsWith(".pub")) {
    commandLog.error("Identity name cannot end with '.pub'");
    return;
  }

  const privateIdentityFile = join(Deno.cwd(), identityName);
  const publicIdentityFile = privateIdentityFile + ".pub";

  const privateIdentityStat = await safeStat(privateIdentityFile);
  const publicIdentityStat = await safeStat(publicIdentityFile);

  if (privateIdentityStat || publicIdentityStat) {
    commandLog.trace("identity private and public files already exists");
    commandLog.error(
      `Found an already existing private and/or public identity file for identity '${identityName}', please remove and try again.`,
    );
    return;
  }

  await Deno.writeTextFile(
    privateIdentityFile,
    pair.privateKey.content.encoded,
  );
  await Deno.writeTextFile(
    publicIdentityFile,
    pair.publicKey.content.decoded.toBase64(),
  );

  commandLog.info(`Identity '${identityName}' successfully generated.`);
}
