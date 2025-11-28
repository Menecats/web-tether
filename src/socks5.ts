import { isIPv4, isIPv6 } from "@std/net/unstable-ip";

const ProtocolVersion = 0x05;
enum ProtocolMethods {
  NO_AUTHENTICATION_REQUIRED = 0x00,
  GSSAPI = 0x01,
  USERNAME_PASSWORD = 0x02,
  // IANA_ASSIGNED = 0x03 -> 0x7F,
  // RESERVED_FOR_PRIVATE_METHODS = 0x80 -> 0xFE,
  NO_ACCEPTABLE_METHODS = 0xFF,
}
enum ProtocolCommand {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}
enum ProtocolAddressType {
  IP_V4 = 0x01,
  DOMAINNAME = 0x03,
  IP_V6 = 0x04,
}
enum ProtocolReply {
  SUCCEEDED = 0x00,
  GENERAL_SOCKS_SERVER_FAILURE = 0x01,
  CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
  NETWORK_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONNECTION_REFUSED = 0x05,
  TTL_EXPIRED = 0x06,
  COMMAND_NOT_SUPPORTED = 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
  // UNASSIGNED = 0x09 -> 0xFF
}

const AuthVersion = 0x01;
enum AuthResult {
  SUCCESS = 0x00,
  FAILURE = 0x01,
}

function concatBuffers(...buffers: Array<Uint8Array | null | undefined>) {
  const length = buffers.reduce((t, b) => t + (b?.length ?? 0), 0);
  const result = new Uint8Array(length);

  let offset = 0;
  for (let i = 0; i < buffers.length; ++i) {
    const buffer = buffers[i];
    if (!buffer) continue;

    result.set(buffer, offset);
    offset += buffer.length;
  }
  return result;
}

function sendSocksReply(
  connection: Deno.TcpConn,
  reply: ProtocolReply,
  boundAddr = "0.0.0.0",
  boundPort = 0,
) {
  console.log(
    `sending response to client ${
      ProtocolReply[reply]
    }, '${boundAddr}', ${boundPort}`,
  );

  // build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
  let addrBuffer: Uint8Array;
  let atyp: ProtocolAddressType;
  if (isIPv4(boundAddr)) {
    atyp = ProtocolAddressType.IP_V4;
    addrBuffer = new Uint8Array(boundAddr.split(".").map((o) => parseInt(o)));
  } else if (isIPv6(boundAddr)) {
    atyp = ProtocolAddressType.IP_V6;
    addrBuffer = new Uint8Array(16);

    const addrBufferView = new DataView(addrBuffer.buffer);
    boundAddr
      .split(":")
      .forEach((h, i) => {
        const value = parseInt(h, 16);
        addrBufferView.setUint16(
          i * Uint16Array.BYTES_PER_ELEMENT,
          value,
          false,
        );
      });
  } else {
    atyp = ProtocolAddressType.DOMAINNAME;
    const hostBuf = new TextEncoder().encode(boundAddr);
    addrBuffer = concatBuffers(new Uint8Array([hostBuf.length]), hostBuf);
  }

  const portBuf = new Uint8Array(2);
  new DataView(portBuf.buffer).setUint16(0, boundPort, false);

  connection.write(concatBuffers(
    new Uint8Array([ProtocolVersion, reply, 0x00, atyp]),
    addrBuffer,
    portBuf,
  ));
}

function safelyClose(
  closeable: { close(): void } | undefined | null,
) {
  try {
    closeable?.close();
  } catch {
    // Ignore 'close' errors
  }
}

async function handleConnection(
  options: CreateSocks5ServerOptions,
  connection: Deno.TcpConn,
) {
  console.log(`Handling connection`);

  type Stage = "handshake" | "auth" | "request" | "stream";
  let stage: Stage = "handshake";

  let workingBuffer: Uint8Array | undefined;
  const readBuffer = new Uint8Array(8);

  let destination: undefined | {
    mode: "ipv4" | "ipv6" | "domain";
    host: string;
    port: number;
  };

  try {
    while (true) {
      const length = await connection.read(readBuffer);
      if (length == null) return safelyClose(connection);

      workingBuffer = concatBuffers(
        workingBuffer,
        readBuffer.subarray(0, length),
      );

      const decoder = new TextDecoder();

      if (stage === "handshake") {
        if (workingBuffer.length < 2) continue; // need VER + NMETHODS

        const ver = workingBuffer[0];
        const nmethods = workingBuffer[1];

        if (ver !== ProtocolVersion) return safelyClose(connection);

        if (workingBuffer.length < 2 + nmethods) continue; // wait for full list

        const methods = Array.from(workingBuffer.subarray(2, 2 + nmethods));
        workingBuffer = workingBuffer.subarray(2 + nmethods);

        console.log(`got methods`, methods.map((m) => ProtocolMethods[m]));

        let chosen = ProtocolMethods.NO_ACCEPTABLE_METHODS;
        if (
          options.auth.enabled &&
          methods.includes(ProtocolMethods.USERNAME_PASSWORD)
        ) {
          chosen = ProtocolMethods.USERNAME_PASSWORD;
        } else if (
          (!options.auth.enabled || !options.auth.required) &&
          methods.includes(ProtocolMethods.NO_AUTHENTICATION_REQUIRED)
        ) {
          chosen = ProtocolMethods.NO_AUTHENTICATION_REQUIRED;
        }

        console.log(`chose ${ProtocolMethods[chosen]}`);
        connection.write(new Uint8Array([ProtocolVersion, chosen]));

        if (chosen === ProtocolMethods.NO_ACCEPTABLE_METHODS) {
          safelyClose(connection);
          return;
        }

        if (chosen === ProtocolMethods.USERNAME_PASSWORD) {
          stage = "auth";
        } else {
          stage = "request";
        }
      }

      if (stage === "auth") {
        console.log(`handling auth`);
        // RFC1929: VER(1)=0x01, ULEN, UNAME, PLEN, PASSWD
        if (workingBuffer.length < 2) {
          console.log(`need more data`);
          continue; // need at least VER + ULEN
        }

        const ver = workingBuffer[0];
        console.log(`got auth version`, ver);
        if (ver !== AuthVersion) {
          console.log(`invalid auth version`);
          safelyClose(connection);
          return;
        }

        const ulen = workingBuffer[1];
        console.log(`got auth length`, ulen);
        if (workingBuffer.length < 2 + ulen + 1) {
          console.log(`need more data`);
          continue;
        }

        const uname = decoder.decode(workingBuffer.subarray(2, 2 + ulen));
        const plen = workingBuffer[2 + ulen];
        console.log(`got username and password length`, uname, plen);
        if (workingBuffer.length < 2 + ulen + 1 + plen) {
          console.log(`need more data`);
          continue;
        }

        const passwd = decoder.decode(
          workingBuffer.subarray(2 + ulen + 1, 2 + ulen + 1 + plen),
        );
        console.log(`got password`, passwd);

        workingBuffer = workingBuffer.subarray(2 + ulen + 1 + plen);

        console.log(`validating credentials`);
        const ok = options.auth.enabled &&
          await options.auth.validate(uname, passwd);
        connection.write(
          new Uint8Array([
            AuthVersion,
            ok ? AuthResult.SUCCESS : AuthResult.FAILURE,
          ]),
        );
        if (!ok) {
          console.log(`invalid credentials`);
          safelyClose(connection);
          return;
        }
        console.log(`goto request`);
        stage = "request";
      }

      if (stage === "request") {
        console.log(`handling request`);
        // need at least 4 bytes to know ATYP: VER, CMD, RSV, ATYP
        if (workingBuffer.length < 4) {
          console.log(`need more data`);
          continue;
        }
        const ver = workingBuffer[0];
        console.log(`got version`, ver);

        if (ver !== ProtocolVersion) {
          console.log(`unsupported version`);
          safelyClose(connection);
          return;
        }

        const cmd = workingBuffer[1];
        console.log(`got command`, ProtocolCommand[cmd]);
        if (cmd !== ProtocolCommand.CONNECT) {
          console.log(`unsupported command`);
          sendSocksReply(connection, ProtocolReply.COMMAND_NOT_SUPPORTED);
          safelyClose(connection);
          return;
        }

        // const rsv = acc[2];

        const workingBufferView = new DataView(
          workingBuffer.buffer,
          workingBuffer.byteOffset,
          workingBuffer.byteLength,
        );

        const atyp = workingBuffer[3];
        let offset = 4;
        if (atyp === ProtocolAddressType.IP_V4) {
          console.log(`handling ipv4`);
          if (workingBuffer.length < offset + 4 + 2) {
            console.log(`need more data`);
            continue; // Wait for a complete ipv4 and port
          }

          const mode = "ipv4";
          const host = Array.from(
            workingBuffer.subarray(offset, offset + 4),
          ).join(
            ".",
          );
          offset += 4;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode, host, port };
        } else if (atyp === ProtocolAddressType.IP_V6) {
          console.log(`handling ipv6`);
          if (workingBuffer.length < offset + 16 + 2) {
            console.log(`need more data`);
            continue; // Wait for a copmlete ipv6 and port
          }

          const parts = [];
          for (let i = 0; i < 16; i += 2) {
            parts.push(
              workingBufferView.getUint16(offset + i, false).toString(16),
            );
          }

          const mode = "ipv6";
          const host = parts.join(":");
          offset += 16;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode, host, port };
        } else if (atyp === ProtocolAddressType.DOMAINNAME) {
          console.log(`handling domain`);
          if (workingBuffer.length < offset + 1) {
            console.log(`need more data`);
            continue; // Wait for domain length
          }
          const len = workingBuffer[offset];
          console.log(`got domain length`, len);
          offset += 1;
          if (workingBuffer.length < offset + len + 2) {
            console.log(`need more data`);
            continue; // Wait for domain and port;
          }

          const mode = "domain";
          const host = decoder.decode(
            workingBuffer.subarray(offset, offset + len),
          );
          offset += len;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode, host, port };
        } else {
          console.log(`unsupported address`);
          sendSocksReply(connection, ProtocolReply.ADDRESS_TYPE_NOT_SUPPORTED);
          safelyClose(connection);
          return;
        }

        console.log(`got destination`, destination);

        workingBuffer = workingBuffer.subarray(offset); // leftover for future (should be empty)
        stage = "stream";
        console.log(`goto stream`);
        break;
      }
    }
  } catch (err) {
    console.log(`got error handling initial stages`, err);
    try {
      sendSocksReply(connection, ProtocolReply.GENERAL_SOCKS_SERVER_FAILURE);
    } catch (e) {
      console.log(`got error notifying failure`, e);
    } finally {
      safelyClose(connection);
    }
  }

  if (stage !== "stream" || !destination || !workingBuffer) {
    console.log(`unexpected state`);
    return;
  }

  console.log(`handling stream (remaining bytes ${workingBuffer.length})`);

  let connected = false;

  let targetConnection: Deno.TcpConn | undefined;

  try {
    console.log(`trying to connect to destination`, destination);

    // now try connect to destination
    // For destinationMode === 'domain', we'll let connect handle resolution (or optionally use a custom dns lookup)
    targetConnection = await Deno.connect({
      hostname: destination.host,
      port: destination.port,
    });
    connected = true;

    sendSocksReply(
      connection,
      ProtocolReply.SUCCEEDED,
      targetConnection.localAddr.hostname,
      targetConnection.localAddr.port,
    );

    await targetConnection.write(workingBuffer);
    await Promise.all([
      connection.readable.pipeTo(targetConnection.writable),
      targetConnection.readable.pipeTo(connection.writable),
    ]).catch((err) => {
      if (!(err instanceof Deno.errors.Interrupted)) {
        console.log(`got error while piping data`, err);
      }
    });
  } catch (err) {
    if (!connected) {
      if (err instanceof Deno.errors.ConnectionRefused) {
        sendSocksReply(connection, ProtocolReply.CONNECTION_REFUSED);
      } else if (err instanceof Deno.errors.NetworkUnreachable) {
        sendSocksReply(connection, ProtocolReply.NETWORK_UNREACHABLE);
      } else {
        sendSocksReply(
          connection,
          ProtocolReply.GENERAL_SOCKS_SERVER_FAILURE,
        );
      }
    }
  } finally {
    safelyClose(targetConnection);
    safelyClose(connection);
  }
}

export type AuthenticationOptions =
  | { enabled: false }
  | {
    enabled: true;
    required: boolean;
    validate: (
      username: string,
      password: string,
    ) => boolean | Promise<boolean>;
  };

export type CreateSocks5ServerOptions = {
  listen: Deno.TcpListenOptions;
  auth: AuthenticationOptions;
};
export function createSocks5Server(options: CreateSocks5ServerOptions) {
  console.log(`Starting server`);
  const listener = Deno.listen(options.listen);

  const done = (async () => {
    console.log(`Waiting for connections`);
    const allConnections = new Set<ReturnType<typeof handleConnection>>();
    for await (const connection of listener) {
      console.log(`Got connection`);
      const connectionDone = handleConnection(options, connection);

      allConnections.add(connectionDone);

      console.log(`Waiting for connection to complete`);
      connectionDone
        .catch((error) => {
          console.log(`got error while handling client`, error);
        })
        .finally(() => allConnections.delete(connectionDone));
    }
  })();

  return done;
}

await createSocks5Server({
  listen: { port: 1080 },
  auth: {
    enabled: false,
  },
});
