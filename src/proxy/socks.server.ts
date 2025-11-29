import { concatBuffers, safelyClose } from "../utils.ts";
import {
  Logger,
  SocksHandler,
  SocksHandlerBufferRequest,
  SocksTunnel,
  SocksTunneler,
} from "./socks.common.ts";
import { handleSocks4, Socks4Version } from "./socks4.handler.ts";
import { handleSocks5, Socks5Version } from "./socks5.handler.ts";

export type Socks5Options =
  | { enabled: false }
  | {
    enabled: true;
    auth:
      | { enabled: false }
      | {
        enabled: true;
        required: boolean;
        validate: (
          username: string,
          password: string,
        ) => Promise<boolean>;
      };
  };

export type Socks4Options =
  | { enabled: false }
  | {
    enabled: true;
    auth:
      | { enabled: false }
      | {
        enabled: true;
        validate: (
          user: string,
        ) => Promise<"valid" | "no-provider" | "no-match">;
      };
  };

export type CreateSocksServerOptions = {
  listen: Deno.TcpListenOptions;
  signal: AbortSignal;

  socks4: Socks4Options;
  socks5: Socks5Options;

  log: Logger;
  tunnel: SocksTunneler;
};
export async function createSocksServer(options: CreateSocksServerOptions) {
  if (options.signal.aborted) throw new Error("Already aborted");

  options.log("info", "Starting server");
  const listener = Deno.listen(options.listen);

  const closeListener = () => listener.close();
  options.signal.addEventListener("abort", closeListener, { once: true });

  // Store all active connections
  const allConnections = new Set<ReturnType<typeof handleConnection>>();

  // Listen for new connections
  options.log("info", "Listening for connections");
  for await (const connection of listener) {
    if (options.signal.aborted) {
      options.log("debug", `Got connection in aborted listener, closing.`);
      safelyClose(connection);
      break;
    }

    const connectionId = crypto.randomUUID();
    options.log("debug", `[${connectionId}]: New connection`);
    const connectionDone = handleConnection(options, connection, connectionId);

    // Register active connection
    allConnections.add(connectionDone);

    // Once done deregister active connection
    connectionDone
      .catch((error) => {
        options.log(
          "error",
          `[${connectionId}]: Error while handling client`,
          error,
        );
      })
      .finally(() => {
        options.log("trace", `[${connectionId}]: Removing connection`);
        allConnections.delete(connectionDone);
      });
  }

  options.signal.removeEventListener("abort", closeListener);

  // Wait for all pending active connections to complete
  await Promise.all([...allConnections]);
}

async function handleConnection(
  options: CreateSocksServerOptions,
  connection: Deno.TcpConn,
  connectionId: string,
) {
  const readBuffer = new Uint8Array(256);

  let workingBuffer: Uint8Array | undefined;
  let bufferRequest: SocksHandlerBufferRequest = { size: 0 };

  options.log("trace", `[${connectionId}]: Creating protocol manager`);

  const protocolManager = handleProtocolSelection(
    options,
    connection,
    connectionId,
  );

  let tunnel: SocksTunnel | undefined;

  try {
    handshake:
    while (true) {
      if (options.signal.aborted) {
        protocolManager.return(undefined);
        break handshake;
      }

      const length = await connection.read(readBuffer);
      if (length == null) return safelyClose(connection);

      workingBuffer = concatBuffers(
        workingBuffer,
        readBuffer.subarray(0, length),
      );

      while (
        ("size" in bufferRequest)
          ? bufferRequest.size <= workingBuffer.length
          : workingBuffer.indexOf(bufferRequest.until) >= 0
      ) {
        if (options.signal.aborted) {
          protocolManager.return(undefined);
          break handshake;
        }

        const readTo = "size" in bufferRequest
          ? bufferRequest.size < 0 ? workingBuffer.length : bufferRequest.size
          : workingBuffer.indexOf(bufferRequest.until) + 1;

        const resultBuffer = workingBuffer.subarray(0, readTo);
        const resultView = new DataView(
          resultBuffer.buffer,
          resultBuffer.byteOffset,
          resultBuffer.byteLength,
        );

        if (!bufferRequest.doNotConsume) {
          workingBuffer = workingBuffer.subarray(readTo);
        }

        const result = await protocolManager.next({
          buffer: resultBuffer,
          view: resultView,
        });

        if (result.done) {
          tunnel = result.value;
          break handshake;
        }

        bufferRequest = result.value;
      }
    }

    if (!options.signal.aborted && tunnel) {
      if (workingBuffer?.length) await tunnel.write(workingBuffer);

      await Promise.all([
        connection.readable.pipeTo(tunnel.writable),
        tunnel.readable.pipeTo(connection.writable),
      ]);
    }
  } finally {
    safelyClose(connection);
    safelyClose(tunnel);
  }
}

async function* handleProtocolSelection(
  options: CreateSocksServerOptions,
  connection: Deno.TcpConn,
  connectionId: string,
): SocksHandler {
  const { view } = yield { size: 1, doNotConsume: true };
  const version = view.getUint8(0);

  if (version === Socks4Version) {
    if (options.socks4.enabled) {
      return yield* handleSocks4(options, connection, connectionId);
    } else {
      // TODO: Socks4 not enabled
      return;
    }
  }

  if (version === Socks5Version) {
    if (options.socks5.enabled) {
      return yield* handleSocks5(options, connection, connectionId);
    } else {
      // TODO: Socks5 not enabled
      return;
    }
  }

  // TODO: Unknown protocol version
}
