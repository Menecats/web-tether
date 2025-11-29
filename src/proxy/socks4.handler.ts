import type { SocksHandler } from "./socks.common.ts";
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
  connection: Deno.TcpConn,
  connectionId: string,
): SocksHandler {
  const { socks4 } = options;
  if (!socks4.enabled) return undefined;

  const { buffer, view } = yield { size: 8 };

  const version = view.getUint8(0);
  if (version !== 0x04) return undefined; // Invalid version

  const command = view.getUint8(1);
  if (command !== Socks4Command.CONNECT) {
    await connection.write(createResponse(Socks4Reply.FAILURE));
    return undefined;
  }

  const destinationPort = view.getUint16(2);

  let destinationMode: "ipv4" | "domain" = "ipv4";
  let destinationHost = buffer.subarray(4).join(".");

  const decoder = new TextDecoder();

  const userIdentifierBuffer = (yield { until: 0x00 }).buffer;
  const userIdentifier = decoder.decode(
    userIdentifierBuffer.subarray(0, userIdentifierBuffer.length - 1),
  );

  if (socks4.auth.enabled) {
    const result = await socks4.auth.validate(userIdentifier);
    if (result === "no-provider") {
      await connection.write(
        createResponse(Socks4Reply.USER_REJECTED_NO_PROVIDER),
      );
      return undefined;
    }
    if (result === "no-match") {
      await connection.write(
        createResponse(Socks4Reply.USER_REJECTED_NO_MATCH),
      );
      return undefined;
    }
  }

  if (destinationHost.startsWith("0.0.0.") && destinationHost !== "0.0.0.0") {
    destinationMode = "domain";
    const destinationHostBuffer = (yield { until: 0x00 }).buffer;
    destinationHost = decoder.decode(
      destinationHostBuffer.subarray(0, destinationHostBuffer.length - 1),
    );
  }

  const tunnelResponse = await options.tunnel({
    mode: destinationMode,
    host: destinationHost,
    port: destinationPort,
  });

  if (tunnelResponse.ok) {
    await connection.write(createResponse(Socks4Reply.SUCCESS));
    return tunnelResponse.tunnel;
  } else {
    await connection.write(createResponse(Socks4Reply.FAILURE));
    return undefined;
  }
}
