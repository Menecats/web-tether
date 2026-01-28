import { LogLevel } from "../../common/log.ts";

export type TunnelErrorReason =
  | { reason: "unknown-error"; error: unknown }
  | { reason: "timeout" }
  | { reason: "buffer-too-short" }
  | { reason: "unknown-version"; version: number }
  | { reason: "cipher-error"; error: unknown; action: "encrypt" | "decrypt" }
  | {
    reason: "auth-mode-unexpected";
    receivedAuth: number;
    expectedAuth: number;
  }
  | { reason: "socket-error"; error: unknown }
  | { reason: "socket-closed" }
  | { reason: "application-aborted" };

export type TunnelClientErrorReason =
  | TunnelErrorReason
  | {
    reason: "invalid-configuration";
    details:
      | "client-keys"
      | "duplicate-bound-services"
      | "duplicate-bound-addresses";
  };
export class TunnelClientError {
  constructor(public readonly reason: TunnelClientErrorReason) {}
}

export type TunnelServerErrorReason =
  | TunnelErrorReason
  | { reason: "unknown-auth"; auth: number }
  | { reason: "auth-challenge-failed" }
  | { reason: "auth-unknown-client" }
  | {
    reason: "invalid-configuration";
    details: "server-keys";
  };
export class TunnelServerError {
  constructor(public readonly reason: TunnelServerErrorReason) {}
}

export function errorLevel(error: unknown): LogLevel {
  if (error instanceof Deno.errors.Interrupted) return "trace";
  if (error instanceof Deno.errors.UnexpectedEof) return "trace";

  if (
    (error instanceof TunnelClientError) ||
    (error instanceof TunnelServerError)
  ) {
    const { reason } = error;

    if (reason.reason === "application-aborted") return "debug";
    if (reason.reason === "socket-closed") return "debug";
    if (reason.reason === "timeout") return "info";
    if (reason.reason === "socket-error") {
      if (reason.error instanceof Deno.errors.Interrupted) return "trace";
      if (reason.error instanceof Deno.errors.UnexpectedEof) return "trace";
    }
  }

  return "error";
}
