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
  uuid: string,
  connection: Deno.TcpConn,
) {
  type Stage = "handshake" | "auth" | "request" | "stream";
  let stage: Stage = "handshake";

  let workingBuffer: Uint8Array | undefined;
  const readBuffer = new Uint8Array(256);

  let destination: undefined | {
    mode: "ipv4" | "ipv6" | "domain";
    host: string;
    port: number;
  };

  try {
    options.log("debug", `[${uuid}]: Setup connection.`);

    const decoder = new TextDecoder();

    while (true) {
      options.log("trace", `[${uuid}]: Reading data from connection.`);

      const length = await connection.read(readBuffer);
      if (length == null) {
        options.log("debug", `[${uuid}]: End of stream reached, closing.`);
        return safelyClose(connection);
      }

      workingBuffer = concatBuffers(
        workingBuffer,
        readBuffer.subarray(0, length),
      );

      options.log(
        "trace",
        `[${uuid}]: Read ${
          stage === "auth" ? "{redacted}" : length
        } bytes from connection, buffer now contains ${
          stage === "auth" ? "{redacted}" : workingBuffer.length
        } bytes.`,
      );

      if (stage === "handshake") {
        options.log("trace", `[${uuid}]: Stage: 'handshake'.`);

        if (workingBuffer.length < 2) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: ${2} bytes required, found ${workingBuffer.length} bytes.`,
          );
          continue; // need VER + NMETHODS
        }

        const socksVersion = workingBuffer[0];
        const methodsCount = workingBuffer[1];

        options.log(
          "trace",
          `[${uuid}]: Got socks version (${socksVersion}) and methods count (${methodsCount}).`,
        );

        if (socksVersion !== ProtocolVersion) {
          options.log(
            "debug",
            `[${uuid}]: Unsupported protocol version: ${socksVersion}, closing.`,
          );
          return safelyClose(connection);
        }

        if (workingBuffer.length < 2 + methodsCount) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: ${
              2 + methodsCount
            } bytes required, found ${workingBuffer.length} bytes.`,
          );
          continue; // wait for full list
        }

        const availableAuthenticationMethods = Array.from(
          workingBuffer.subarray(2, 2 + methodsCount),
        );
        workingBuffer = workingBuffer.subarray(2 + methodsCount);

        options.log(
          "trace",
          `[${uuid}]: Got authentication methods: ${
            availableAuthenticationMethods.map((m) =>
              ProtocolMethods[m] || `<unknown:${m}>`
            ).join(
              ",",
            )
          }.`,
        );

        options.log(
          "trace",
          `[${uuid}]: Choosing authentication method given local configuration (enabled: ${options.auth.enabled}${
            options.auth.enabled ? `, required: ${options.auth.required}` : ""
          }).`,
        );

        let chosenAuthenticationMethod = ProtocolMethods.NO_ACCEPTABLE_METHODS;
        if (
          options.auth.enabled &&
          availableAuthenticationMethods.includes(
            ProtocolMethods.USERNAME_PASSWORD,
          )
        ) {
          chosenAuthenticationMethod = ProtocolMethods.USERNAME_PASSWORD;
        } else if (
          (!options.auth.enabled || !options.auth.required) &&
          availableAuthenticationMethods.includes(
            ProtocolMethods.NO_AUTHENTICATION_REQUIRED,
          )
        ) {
          chosenAuthenticationMethod =
            ProtocolMethods.NO_AUTHENTICATION_REQUIRED;
        }

        options.log(
          "trace",
          `[${uuid}]: Authentication method chosen: ${
            ProtocolMethods[chosenAuthenticationMethod] ||
            `<unknown:${chosenAuthenticationMethod}>`
          }.`,
        );

        connection.write(
          new Uint8Array([ProtocolVersion, chosenAuthenticationMethod]),
        );

        if (
          chosenAuthenticationMethod === ProtocolMethods.NO_ACCEPTABLE_METHODS
        ) {
          options.log(
            "debug",
            `[${uuid}]: No available authentication methods found.`,
          );
          return safelyClose(connection);
        }

        if (chosenAuthenticationMethod === ProtocolMethods.USERNAME_PASSWORD) {
          stage = "auth";
        } else {
          stage = "request";
        }
      }

      if (stage === "auth") {
        options.log("trace", `[${uuid}]: Stage: 'auth'.`);

        // RFC1929: VER(1)=0x01, ULEN, UNAME, PLEN, PASSWD
        if (workingBuffer.length < 2) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: ${2} bytes required, found ${workingBuffer.length} bytes.`,
          );
          continue; // need at least VER + ULEN
        }

        const authenticationVersion = workingBuffer[0];
        options.log(
          "trace",
          `[${uuid}]: Got authentication version (${authenticationVersion}).`,
        );

        if (authenticationVersion !== AuthVersion) {
          options.log(
            "debug",
            `[${uuid}]: Unsupported authentication version: ${authenticationVersion}, closing.`,
          );
          return safelyClose(connection);
        }

        const usernameLength = workingBuffer[1];
        options.log("trace", `[${uuid}]: Got username length.`);

        if (workingBuffer.length < 2 + usernameLength + 1) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: {redacted} bytes required, found {redacted} bytes.`,
          );
          continue;
        }

        const username = decoder.decode(
          workingBuffer.subarray(2, 2 + usernameLength),
        );
        const passwordLength = workingBuffer[2 + usernameLength];

        options.log("trace", `[${uuid}]: Got username and password length.`);
        if (workingBuffer.length < 2 + usernameLength + 1 + passwordLength) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: {redacted} bytes required, found {redacted} bytes.`,
          );
          continue;
        }

        const password = decoder.decode(
          workingBuffer.subarray(
            2 + usernameLength + 1,
            2 + usernameLength + 1 + passwordLength,
          ),
        );
        options.log("trace", `[${uuid}]: Got password.`);

        workingBuffer = workingBuffer.subarray(
          2 + usernameLength + 1 + passwordLength,
        );

        options.log("trace", `[${uuid}]: Validating credentials.`);
        const authenticationResult = (options.auth.enabled &&
            await options.auth.validate(username, password))
          ? AuthResult.SUCCESS
          : AuthResult.FAILURE;

        options.log(
          "trace",
          `[${uuid}]: Authentication result: ${
            AuthResult[authenticationResult] ||
            `<unknown:${authenticationResult}>`
          }.`,
        );

        connection.write(new Uint8Array([AuthVersion, authenticationResult]));
        if (authenticationResult !== AuthResult.SUCCESS) {
          options.log(
            "debug",
            `[${uuid}]: Authentication failed, closing.`,
          );
          return safelyClose(connection);
        }

        stage = "request";
      }

      if (stage === "request") {
        options.log("trace", `[${uuid}]: Stage: 'request'.`);

        // need at least 4 bytes to know ATYP: VER, CMD, RSV, ATYP
        if (workingBuffer.length < 4) {
          options.log(
            "trace",
            `[${uuid}]: Not enough data on buffer: ${4} bytes required, found ${workingBuffer.length} bytes.`,
          );
          continue;
        }

        const socksVersion = workingBuffer[0];
        const command = workingBuffer[1];
        // rsv = workingBuffer[2];
        const addressType = workingBuffer[3];

        options.log(
          "trace",
          `[${uuid}]: Got socks version (${socksVersion}), command (${
            ProtocolCommand[command] || `<unknown:${command}>`
          }) and address type (${
            ProtocolAddressType[addressType] || `<unknown:${addressType}>`
          }).`,
        );

        if (socksVersion !== ProtocolVersion) {
          options.log(
            "debug",
            `[${uuid}]: Unsupported protocol version: ${socksVersion}, closing.`,
          );
          return safelyClose(connection);
        }

        if (command !== ProtocolCommand.CONNECT) {
          options.log(
            "debug",
            `[${uuid}]: Unsupported command ${
              ProtocolCommand[command] || `<unknown:${command}>`
            }.`,
          );
          sendSocksReply(connection, ProtocolReply.COMMAND_NOT_SUPPORTED);
          return safelyClose(connection);
        }

        const workingBufferView = new DataView(
          workingBuffer.buffer,
          workingBuffer.byteOffset,
          workingBuffer.byteLength,
        );

        options.log("trace", `[${uuid}]: Parsing destination address.`);

        let offset = 4;
        if (addressType === ProtocolAddressType.IP_V4) {
          options.log("trace", `[${uuid}]: Parsing IPv4 address.`);
          if (workingBuffer.length < offset + 4 + 2) {
            options.log(
              "trace",
              `[${uuid}]: Not enough data on buffer: ${
                offset + 4 + 2
              } bytes required, found ${workingBuffer.length} bytes.`,
            );
            continue; // Wait for a complete ipv4 and port
          }

          const host = Array.from(
            workingBuffer.subarray(offset, offset + 4),
          ).join(
            ".",
          );
          offset += 4;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode: "ipv4", host, port };
        } else if (addressType === ProtocolAddressType.IP_V6) {
          options.log("trace", `[${uuid}]: Parsing IPv6 address.`);
          if (workingBuffer.length < offset + 16 + 2) {
            options.log(
              "trace",
              `[${uuid}]: Not enough data on buffer: ${
                offset + 16 + 2
              } bytes required, found ${workingBuffer.length} bytes.`,
            );
            continue; // Wait for a copmlete ipv6 and port
          }

          const parts = [];
          for (let i = 0; i < 16; i += 2) {
            parts.push(
              workingBufferView.getUint16(offset + i, false).toString(16),
            );
          }

          const host = parts.join(":");
          offset += 16;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode: "ipv6", host, port };
        } else if (addressType === ProtocolAddressType.DOMAINNAME) {
          options.log("trace", `[${uuid}]: Parsing domain name.`);
          if (workingBuffer.length < offset + 1) {
            options.log(
              "trace",
              `[${uuid}]: Not enough data on buffer: ${
                offset + 1
              } bytes required, found ${workingBuffer.length} bytes.`,
            );
            continue; // Wait for domain length
          }

          const hostLength = workingBuffer[offset];
          offset += 1;
          options.log(
            "trace",
            `[${uuid}]: Got domain name length (${hostLength}).`,
          );

          if (workingBuffer.length < offset + hostLength + 2) {
            options.log(
              "trace",
              `[${uuid}]: Not enough data on buffer: ${
                offset + hostLength + 2
              } bytes required, found ${workingBuffer.length} bytes.`,
            );
            continue; // Wait for domain and port;
          }

          const host = decoder.decode(
            workingBuffer.subarray(offset, offset + hostLength),
          );
          offset += hostLength;

          const port = workingBufferView.getUint16(offset, false);
          offset += 2;

          destination = { mode: "domain", host, port };
        } else {
          options.log(
            "debug",
            `[${uuid}]: Unsupported address type ${
              ProtocolAddressType[addressType] || `<unknown:${addressType}>`
            }.`,
          );
          sendSocksReply(connection, ProtocolReply.ADDRESS_TYPE_NOT_SUPPORTED);
          return safelyClose(connection);
        }

        options.log(
          "trace",
          `[${uuid}]: Got destination host (${destination.host}) and port (${destination.port}).`,
        );

        workingBuffer = workingBuffer.subarray(offset); // leftover for future (should be empty)

        if (workingBuffer.length) {
          options.log(
            "trace",
            `[${uuid}]: After setup there are still ${workingBuffer.length} bytes in the buffer.`,
          );
        }

        stage = "stream";
        break;
      }
    }
  } catch (err) {
    options.log(
      "error",
      `[${uuid}]: Error while handling connection setup, closing.`,
      err,
    );
    try {
      sendSocksReply(connection, ProtocolReply.GENERAL_SOCKS_SERVER_FAILURE);
    } catch (e) {
      options.log(
        "trace",
        `[${uuid}]: Error notifying failure to client, still closing.`,
        e,
      );
    } finally {
      safelyClose(connection);
    }
  }

  if (stage !== "stream" || !destination || !workingBuffer) return;

  options.log("debug", `[${uuid}]: Setup completed.`);

  let connected = false;
  let targetConnection: Deno.TcpConn | undefined;

  try {
    options.log("debug", `[${uuid}]: Connecting to destination.`, destination);

    // TODO: Implement dns lookup and filtering

    targetConnection = await Deno.connect({
      hostname: destination.host,
      port: destination.port,
    });
    connected = true;

    options.log(
      "trace",
      `[${uuid}]: Connected to ${targetConnection.remoteAddr.hostname}:${targetConnection.remoteAddr.port} from ${targetConnection.localAddr.hostname}:${targetConnection.localAddr.port}.`,
    );

    sendSocksReply(
      connection,
      ProtocolReply.SUCCEEDED,
      targetConnection.localAddr.hostname,
      targetConnection.localAddr.port,
    );

    if (workingBuffer.length) {
      options.log(
        "trace",
        `[${uuid}]: Writing remaining buffer (${workingBuffer.length} bytes).`,
      );
      await targetConnection.write(workingBuffer);
    }

    options.log(
      "debug",
      `[${uuid}]: Piping connection.`,
    );
    await Promise.all([
      connection.readable.pipeTo(targetConnection.writable),
      targetConnection.readable.pipeTo(connection.writable),
    ]).catch((err) => {
      if (!(err instanceof Deno.errors.Interrupted)) {
        options.log(
          "error",
          `[${uuid}]: Error while piping data, closing.`,
          err,
        );
      }
    });
  } catch (err) {
    options.log(
      "trace",
      `[${uuid}]: Error while connecting to remote destination, closing.`,
      err,
    );

    if (!connected) {
      try {
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
      } catch (e) {
        options.log(
          "trace",
          `[${uuid}]: Error notifying failure to client, still closing.`,
          e,
        );
      }
    }
  } finally {
    safelyClose(targetConnection);
    safelyClose(connection);
  }
}

export type CreateSocks5ServerOptions = {
  listen: Deno.TcpListenOptions;
  auth:
    | { enabled: false }
    | {
      enabled: true;
      required: boolean;
      validate: (
        username: string,
        password: string,
      ) => boolean | Promise<boolean>;
    };
  log: (
    level: "trace" | "debug" | "info" | "error",
    ...content: unknown[]
  ) => void;
};
export async function createSocks5Server(options: CreateSocks5ServerOptions) {
  const listener = Deno.listen(options.listen);

  // Store all active connections
  const allConnections = new Set<ReturnType<typeof handleConnection>>();

  // Listen for new connections
  for await (const connection of listener) {
    const uuid = crypto.randomUUID();
    options.log("debug", `[${uuid}]: New connection`);
    const connectionDone = handleConnection(options, uuid, connection);

    // Register active connection
    allConnections.add(connectionDone);

    // Once done deregister active connection
    connectionDone
      .catch((error) => {
        options.log("error", `[${uuid}]: Error while handling client`, error);
      })
      .finally(() => {
        options.log("trace", `[${uuid}]: Removing connection`);
        allConnections.delete(connectionDone);
      });
  }

  // Wait for all pending active connections to complete
  await Promise.all([...allConnections]);
}

await createSocks5Server({
  listen: { port: 1080 },
  auth: {
    enabled: false,
  },
  log: (level, ...content) => console.log(level, ...content),
});
