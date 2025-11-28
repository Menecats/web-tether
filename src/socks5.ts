import { isIPv4, isIPv6 } from "@std/net/unstable-ip";

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

async function handleConnection(
  options: CreateSocks5ServerOptions,
  connection: Deno.TcpConn,
) {
  console.log(`Handling connection`);

  function sendSocksReply(
    repCode: number,
    boundAddr = "0.0.0.0",
    boundPort = 0,
  ) {
    console.log(
      `sending response to client ${repCode}, '${boundAddr}', ${boundPort}`,
    );

    // build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    let addrBuffer;
    let atyp;
    if (isIPv4(boundAddr)) {
      atyp = ATYP_IPV4;
      addrBuffer = new Uint8Array(boundAddr.split(".").map((o) => parseInt(o)));
    } else if (isIPv6(boundAddr)) {
      atyp = ATYP_IPV6;
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
      atyp = ATYP_DOMAIN;
      const hostBuf = new TextEncoder().encode(boundAddr);
      addrBuffer = concatBuffers(new Uint8Array([hostBuf.length]), hostBuf);
    }

    const portBuf = new Uint8Array(2);
    new DataView(portBuf.buffer).setUint16(0, boundPort, false);

    const reply = concatBuffers(
      new Uint8Array([VER, repCode, 0x00, atyp]),
      addrBuffer,
      portBuf,
    );
    connection.write(reply);
  }

  // SOCKS5 constants
  const VER = 0x05;
  const AUTH_NO = 0x00;
  const AUTH_USERPASS = 0x02;
  const AUTH_NO_ACCEPTABLE = 0xff;

  const CMD_CONNECT = 0x01;

  const ATYP_IPV4 = 0x01;
  const ATYP_DOMAIN = 0x03;
  const ATYP_IPV6 = 0x04;

  // Reply codes (RFC1928)
  const REP = {
    SUCCESS: 0x00,
    GENERAL_FAILURE: 0x01,
    NOT_ALLOWED: 0x02,
    NETWORK_UNREACHABLE: 0x03,
    HOST_UNREACHABLE: 0x04,
    CONNECTION_REFUSED: 0x05,
    TTL_EXPIRED: 0x06,
    CMD_NOT_SUPPORTED: 0x07,
    ADDR_TYPE_NOT_SUPPORTED: 0x08,
  };

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
      if (length == null) {
        console.log(`No more data to read`);

        connection.close();
        return;
      }

      console.log(`got data (${length} bytes)`);

      workingBuffer = concatBuffers(
        workingBuffer,
        readBuffer.subarray(0, length),
      );

      const decoder = new TextDecoder();

      if (stage === "handshake") {
        console.log(`handling handshake`);
        if (workingBuffer.length < 2) {
          console.log(`need more data`);
          continue; // need VER + NMETHODS
        }

        const ver = workingBuffer[0];
        const nmethods = workingBuffer[1];

        console.log(`got version and methods count`, ver, nmethods);

        if (ver !== VER) {
          console.log(`invalid version`);
          connection.close();
          return;
        }

        if (workingBuffer.length < 2 + nmethods) {
          console.log(`need more data`);
          continue; // wait for full list
        }

        const methods = Array.from(workingBuffer.subarray(2, 2 + nmethods));
        workingBuffer = workingBuffer.subarray(2 + nmethods);

        console.log(`got methods`, methods);

        console.log(`handling auth`);

        // TODO: Review auth
        let chosen = AUTH_NO;
        if (options.auth.enabled && methods.includes(AUTH_USERPASS)) {
          console.log(`choosing credentials`);
          chosen = AUTH_USERPASS;
        } else if (!methods.includes(AUTH_NO) && chosen === AUTH_NO) {
          console.log(`unsupported auth`);

          // no acceptable
          connection.write(new Uint8Array([VER, AUTH_NO_ACCEPTABLE]));
          connection.close();
          return;
        }
        console.log(`chose ${chosen}`);
        connection.write(new Uint8Array([VER, chosen]));

        if (chosen === AUTH_USERPASS) {
          console.log(`goto auth`);
          stage = "auth";
        } else {
          console.log(`goto request`);
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
        if (ver !== 0x01) {
          console.log(`invalid auth version`);
          connection.close();
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
        const ok = await options.auth.validate(uname, passwd);
        connection.write(new Uint8Array([0x01, ok ? 0x00 : 0x01]));
        if (!ok) {
          console.log(`invalid credentials`);
          connection.close();
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

        if (ver !== VER) {
          console.log(`unsupported version`);
          connection.close();
          return;
        }

        const cmd = workingBuffer[1];
        console.log(`got command`, cmd);
        if (cmd !== CMD_CONNECT) {
          console.log(`unsupported command`);
          sendSocksReply(REP.CMD_NOT_SUPPORTED);
          connection.close();
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
        if (atyp === ATYP_IPV4) {
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
        } else if (atyp === ATYP_IPV6) {
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
        } else if (atyp === ATYP_DOMAIN) {
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
          sendSocksReply(REP.ADDR_TYPE_NOT_SUPPORTED);
          connection.close();
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
      sendSocksReply(REP.GENERAL_FAILURE);
    } catch (e) {
      console.log(`got error notifying failure`, e);
    } finally {
      connection.close();
    }
  }

  if (stage !== "stream" || !destination || !workingBuffer) {
    console.log(`unexpected state`);
    return;
  }

  console.log(`handling stream (remaining bytes ${workingBuffer.length})`);

  let connected = false;

  try {
    console.log(`trying to connect to destination`, destination);

    // now try connect to destination
    // For destinationMode === 'domain', we'll let connect handle resolution (or optionally use a custom dns lookup)
    const targetConnection = await Deno.connect({
      hostname: destination.host,
      port: destination.port,
    });
    connected = true;

    console.log(`connected`);

    console.log("repying");
    sendSocksReply(
      REP.SUCCESS,
      targetConnection.localAddr.hostname,
      targetConnection.localAddr.port,
    );

    console.log(`pushing remaining bytes`);
    await targetConnection.write(workingBuffer);

    console.log(`piping content`);
    await Promise.all([
      connection.readable.pipeTo(targetConnection.writable),
      targetConnection.readable.pipeTo(connection.writable),
    ]).catch((err) => {
      if (!(err instanceof Deno.errors.Interrupted)) {
        console.log(`got error while piping data`, err);
      }
    }).finally(() => {
      try {
        connection.close();
      } catch {
      }
      try {
        targetConnection.close();
      } catch {
      }
    });

    console.log(`completed`);
  } catch (err) {
    console.log(`got error while connecting`, err);
    try {
      if (!connected) {
        if (err instanceof Deno.errors.ConnectionRefused) {
          sendSocksReply(REP.CONNECTION_REFUSED);
        } else if (err instanceof Deno.errors.NetworkUnreachable) {
          sendSocksReply(REP.NETWORK_UNREACHABLE);
        } else {
          sendSocksReply(REP.GENERAL_FAILURE);
        }
      }
    } finally {
      try {
        connection.close();
      } catch (e) {
        console.log(`got error notifying failure`, e);
      }
    }
  }
}

export type CreateSocks5ServerOptions = {
  listen: Deno.TcpListenOptions;
  auth: {
    enabled: boolean;
    validate: (
      username: string,
      password: string,
    ) => boolean | Promise<boolean>;
  };
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
  auth: { enabled: false, validate: () => Promise.resolve(false) },
});
