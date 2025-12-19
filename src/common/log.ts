export type Logger = (
  level: "trace" | "debug" | "info" | "error",
  ...content: unknown[]
) => void;
