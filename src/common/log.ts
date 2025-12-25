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

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";
export type LogFunction = (...content: unknown[]) => void;
export type Logger = Record<LogLevel, LogFunction>;

export function createLogger(
  output: (level: LogLevel, content: unknown[]) => void,
): Logger {
  return {
    trace: (...content) => output("trace", content),
    debug: (...content) => output("debug", content),
    info: (...content) => output("info", content),
    warn: (...content) => output("warn", content),
    error: (...content) => output("error", content),
  };
}

export function prefixLogger(
  logger: Logger,
  ...prefix: unknown[]
): Logger {
  const prefixer =
    (fn: LogFunction, context: unknown): LogFunction =>
    (...content: unknown[]) => {
      fn.call(context, ...prefix, ...content);
    };

  return {
    trace: prefixer(logger.trace, logger),
    debug: prefixer(logger.debug, logger),
    info: prefixer(logger.info, logger),
    warn: prefixer(logger.warn, logger),
    error: prefixer(logger.error, logger),
  };
}

export function colorizeOutput(
  filter: (level: LogLevel) => boolean = () => true,
): (
  level: LogLevel,
  content: unknown[],
) => void {
  const levelColors: Record<LogLevel, (content: string) => string> = {
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
    if (!filter(level)) return;

    const colorize = levelColors[level];

    const colorizedContent = content.map((c) => {
      if (typeof c !== "string") return c;

      const [, marker] = markerPattern.exec(c) || [undefined, undefined];
      if (!marker) return colorize(c);

      if (!markerColors.has(marker)) {
        const fg = colorScale(newRNG(marker)()).num() | 0;
        markerColors.set(marker, (v) => rgb24(v, fg));
      }

      return "[" + markerColors.get(marker)!(marker) + "]";
    });

    console.log(
      level,
      ...colorizedContent,
    );
  };
}
