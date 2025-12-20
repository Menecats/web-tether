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
  | { reason: "invalid-configuration"; details: "client-keys" };
export class TunnelClientError {
  constructor(public readonly reason: TunnelClientErrorReason) {}
}

export type TunnelServerErrorReason =
  | TunnelErrorReason
  | { reason: "unknown-auth"; auth: number }
  | { reason: "auth-challenge-failed" }
  | { reason: "auth-unknown-client" };
export class TunnelServerError {
  constructor(public readonly reason: TunnelServerErrorReason) {}
}
