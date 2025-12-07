import { printEnum } from "../common/utils.ts";
import {
  SOCKS_HANDSHAKE_TIMEOUT,
  type SocksDestinationAddress,
  type SocksHandler,
} from "./socks.common.ts";
import { CreateSocksServerOptions } from "./socks.server.ts";

export const Socks4Version = 0x04;
export enum Socks4Command {
  CONNECT = 0x01,
  BIND = 0x02,
}
export enum Socks4Reply {
  SUCCESS = 0x5a,
  FAILURE = 0x5b,

  USER_REJECTED_NO_PROVIDER = 0x5c,
  USER_REJECTED_NO_MATCH = 0x5d,
}

function createResponse(response: Socks4Reply) {
  return new Uint8Array([0x00, response, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

export async function* handleSocks4(
  options: CreateSocksServerOptions,
  writer: { write: (buffer: Uint8Array) => Promise<void> },
): SocksHandler {
  const { socks4 } = options;
  if (!socks4.enabled) return undefined;

  const { buffer, view } = yield { timeout: SOCKS_HANDSHAKE_TIMEOUT, size: 8 };

  const version = view.getUint8(0);
  options.log("trace", `socks4: got version (${version}).`);
  if (version !== 0x04) {
    options.log("trace", `socks4: invalid version.`);
    return undefined;
  }

  const command = view.getUint8(1);
  options.log(
    "trace",
    `socks4: got command (${printEnum(Socks4Command, command)}).`,
  );
  if (command !== Socks4Command.CONNECT) {
    options.log(
      "trace",
      `socks4: unsupported command.`,
    );
    await writer.write(createResponse(Socks4Reply.FAILURE));
    return undefined;
  }

  const destinationPort = view.getUint16(2);
  options.log(
    "trace",
    `socks4: got destination port (${destinationPort}).`,
  );

  let destinationMode: "ipv4" | "domain" = "ipv4";
  let destinationHost = buffer.subarray(4).join(".");
  options.log(
    "trace",
    `socks4: got destination host (${destinationHost}).`,
  );

  const decoder = new TextDecoder();

  const userIdentifierBuffer =
    (yield { timeout: SOCKS_HANDSHAKE_TIMEOUT, until: 0x00 }).buffer;
  const userIdentifier = decoder.decode(
    userIdentifierBuffer.subarray(0, userIdentifierBuffer.length - 1),
  );

  options.log(
    "trace",
    `socks4: got user identifier.`,
  );

  if (socks4.auth.enabled) {
    options.log(
      "trace",
      `socks4: validating used identifier.`,
    );
    const result = await socks4.auth.validate(userIdentifier);
    options.log(
      "trace",
      `socks4: validation result (${result}).`,
    );
    if (result === "no-provider") {
      options.log(
        "trace",
        `socks4: closing.`,
      );
      await writer.write(
        createResponse(Socks4Reply.USER_REJECTED_NO_PROVIDER),
      );
      return undefined;
    }
    if (result === "no-match") {
      options.log(
        "trace",
        `socks4: closing.`,
      );
      await writer.write(
        createResponse(Socks4Reply.USER_REJECTED_NO_MATCH),
      );
      return undefined;
    }
  }

  if (destinationHost.startsWith("0.0.0.") && destinationHost !== "0.0.0.0") {
    options.log(
      "trace",
      `socks4: detected socks4a usage.`,
    );

    destinationMode = "domain";
    const destinationHostBuffer =
      (yield { timeout: SOCKS_HANDSHAKE_TIMEOUT, until: 0x00 }).buffer;
    destinationHost = decoder.decode(
      destinationHostBuffer.subarray(0, destinationHostBuffer.length - 1),
    );

    options.log(
      "trace",
      `socks4: got socks4a destination host (${destinationHost}).`,
    );
  }

  const destination: SocksDestinationAddress = {
    mode: destinationMode,
    host: destinationHost,
    port: destinationPort,
  };

  options.log(
    "trace",
    `socks4: creating tunnel (${destination.host}:${destination.port}).`,
  );
  const tunnelResponse = await options.tunnel(destination, options.log);

  if (tunnelResponse.ok) {
    options.log(
      "trace",
      `socks4: tunnel created successfully.`,
    );
    await writer.write(createResponse(Socks4Reply.SUCCESS));
    return tunnelResponse.tunnel;
  } else {
    options.log(
      "trace",
      `socks4: error creating tunnel (${tunnelResponse.error}).`,
    );
    await writer.write(createResponse(Socks4Reply.FAILURE));
    return undefined;
  }
}
