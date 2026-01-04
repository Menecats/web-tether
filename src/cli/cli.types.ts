import { Logger } from "../common/log.ts";

export type CliCommandOptions = {
  command: string;
  commandArgs: string[];

  commandLog: Logger;
};
