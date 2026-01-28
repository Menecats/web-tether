import {
  brightRed,
  brightYellow,
  gray,
  rgb24,
  white,
  yellow,
} from "@std/fmt/colors";
import chroma from "chroma-js";
import { newRNG } from "./rng.ts";

export const LogLevels = [
  "none",
  "trace",
  "debug",
  "info",
  "warn",
  "error",
] as const;

export type LogLevel = (typeof LogLevels)[number];
export type LogFunction = (...content: unknown[]) => void;
export type Logger = Record<LogLevel, LogFunction> & { parent: Logger };

export function createLogger(
  output: (level: LogLevel, content: unknown[]) => void,
): Logger {
  const partialLogger = Object.fromEntries(LogLevels
    .map((level): [LogLevel, LogFunction] => [
      level,
      (...content) => {
        if (level !== "none") output(level, content);
      },
    ])) as Partial<Logger>;
  partialLogger.parent = partialLogger as Logger;
  return partialLogger as Logger;
}

export function prefixLogger(logger: Logger, ...prefix: unknown[]): Logger {
  const prefixer =
    (fn: LogFunction, context: unknown): LogFunction =>
    (...content: unknown[]) => {
      fn.call(context, ...prefix, ...content);
    };

  return Object.fromEntries([
    ...LogLevels.map((level): [LogLevel, LogFunction] => [
      level,
      prefixer(logger[level], logger),
    ]),
    ["parent", logger],
  ]) as Logger;
}

export type ConfigurableLogger<T> = Logger & {
  configure: (config: T) => void;
};
export type ConfigurablePrefixLoggerOptions<T> = {
  configure: (config: T) => unknown[];
  initial: unknown[];
};
export function configurablePrefixLogger<T>(
  logger: Logger,
  options: ConfigurablePrefixLoggerOptions<T>,
): ConfigurableLogger<T> {
  let prefix = options.initial;
  const prefixer =
    (fn: LogFunction, context: unknown): LogFunction =>
    (...content: unknown[]) => {
      fn.call(context, ...prefix, ...content);
    };

  return Object.fromEntries([
    ...LogLevels.map((level): [LogLevel, LogFunction] => [
      level,
      prefixer(logger[level], logger),
    ]),
    ["parent", logger],
    ["configure", (config: T) => {
      prefix = options.configure(config);
    }],
  ]) as ConfigurableLogger<T>;
}

export function colorizeOutput(
  output: (...args: unknown[]) => void,
  filter: (level: LogLevel) => boolean = () => true,
): (level: LogLevel, content: unknown[]) => void {
  const levelColors: Record<
    Exclude<LogLevel, "none">,
    (content: string) => string
  > = {
    trace: gray,
    debug: yellow,
    info: white,
    warn: brightYellow,
    error: brightRed,
  };
  const markerColors = new Map<string, (content: string) => string>();
  const markerPattern = /^\[([^\]]+)\]$/;

  const colorScale = chroma.scale("Spectral");

  return (level, content) => {
    if (level === "none" || !filter(level)) return;

    const colorize = levelColors[level];

    const colorizedContent = content.map((c) => {
      if (typeof c !== "string") return c;

      const [, marker] = markerPattern.exec(c) || [undefined, undefined];
      if (!marker) return colorize(c);

      const markerChunks = marker.split(":");

      return "[" + markerChunks.map((markerChunk) => {
        if (!markerColors.has(markerChunk)) {
          const fg = colorScale(newRNG(markerChunk)()).num() | 0;
          markerColors.set(markerChunk, (v) => rgb24(v, fg));
        }
        return markerColors.get(markerChunk)!(markerChunk);
      }).join(":") + "]";
    });

    const maxLength = Math.max(...LogLevels.map((l) => l.length));

    output(
      `[${colorize(level.padEnd(maxLength).toUpperCase())}]`,
      ...colorizedContent,
    );
  };
}
