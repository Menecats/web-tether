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
  if (options.signal.aborted) return;

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
    const connectionLog: Logger = (level, ...content) =>
      options.log(level, `[${connectionId}]:`, ...content);

    connectionLog("debug", `New connection.`);
    const connectionDone = handleConnection(
      { ...options, log: connectionLog },
      connection,
    );

    // Register active connection
    allConnections.add(connectionDone);

    // Once done deregister active connection
    connectionDone
      .catch((error) => {
        connectionLog(
          "error",
          `Error while handling connection.`,
          error,
        );
      })
      .finally(() => {
        connectionLog("trace", `Purging connection.`);
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
) {
  const readBuffer = new Uint8Array(256);

  let workingBuffer: Uint8Array | undefined;
  let bufferRequest: SocksHandlerBufferRequest = { size: 0 };

  options.log("debug", `Creating protocol manager`);

  const protocolManager = handleProtocol(
    options,
    connection,
  );

  let tunnel: SocksTunnel | undefined;

  try {
    handshake:
    while (true) {
      if (options.signal.aborted) {
        options.log("trace", `Listener is aborted, closing.`);
        await protocolManager.return(undefined);
        break handshake;
      }

      const length = await connection.read(readBuffer);
      if (length == null) {
        options.log("debug", `End of stream reached, closing.`);
        return;
      }

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
          options.log("trace", `Listener is aborted, closing.`);
          await protocolManager.return(undefined);
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
      if (workingBuffer?.length) {
        options.log(
          "trace",
          `Writing remaining buffer (${workingBuffer.length} bytes).`,
        );
        await tunnel.write(workingBuffer);
      }

      options.log("debug", `Piping connection.`);

      const closeConnections = () => {
        safelyClose(tunnel);
        safelyClose(connection);
      };
      options.signal.addEventListener("abort", closeConnections, {
        once: true,
      });
      try {
        await Promise.all([
          connection.readable.pipeTo(tunnel.writable),
          tunnel.readable.pipeTo(connection.writable),
        ]).catch((err) => {
          if (!(err instanceof Deno.errors.Interrupted)) {
            options.log(
              "error",
              `Error while piping data, closing.`,
              err,
            );
          }
        });
      } finally {
        options.signal.removeEventListener("abort", closeConnections);
      }
    }
  } finally {
    safelyClose(connection);
    safelyClose(tunnel);
  }
}

async function* handleProtocol(
  options: CreateSocksServerOptions,
  connection: Deno.TcpConn,
): SocksHandler {
  options.log("trace", `handler: Reading socks version.`);

  const { view } = yield { size: 1, doNotConsume: true };
  const version = view.getUint8(0);

  if (version === Socks4Version) {
    if (options.socks4.enabled) {
      options.log("trace", `handler: Delegate socks4 handler.`);
      return yield* handleSocks4(options, connection);
    } else {
      options.log("trace", `handler: socks4 handler not enabled, closing.`);
      return;
    }
  }

  if (version === Socks5Version) {
    if (options.socks5.enabled) {
      options.log("trace", `handler: Delegate socks5 handler.`);
      return yield* handleSocks5(options, connection);
    } else {
      options.log("trace", `handler: socks5 handler not enabled, closing.`);
      return;
    }
  }

  options.log("trace", `handler: version (${version}) not supported.`);
}
