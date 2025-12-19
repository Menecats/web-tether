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
