import { deadline } from "@std/async";
import { ConnectionTunnel } from "../common/communication.ts";
import { Logger, prefixLogger } from "../common/log.ts";
import { concatBuffers, safelyClose } from "../common/utils.ts";
import {
  SOCKS_HANDSHAKE_INIT_TIMEOUT,
  SocksHandler,
  SocksHandlerBufferRequest,
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

  options.log.info("Starting server");
  const listener = Deno.listen(options.listen);

  const closeListener = () => listener.close();
  options.signal.addEventListener("abort", closeListener, { once: true });

  // Store all active connections
  const allConnections = new Set<ReturnType<typeof handleSocksConnection>>();

  try {
    // Listen for new connections
    options.log.info("Listening for connections");
    for await (const connection of listener) {
      if (options.signal.aborted) {
        options.log.debug(`Got connection in aborted listener, closing.`);
        safelyClose(connection);
        break;
      }

      const connectionId = crypto.randomUUID();
      const connectionLog: Logger = prefixLogger(
        options.log,
        `[${connectionId}]:`,
      );

      connectionLog.debug(`New connection.`);
      const connectionDone = handleSocksConnection(
        { ...options, log: connectionLog },
        connection,
      );

      // Register active connection
      allConnections.add(connectionDone);

      // Once done deregister active connection
      connectionDone
        .catch((error) => {
          connectionLog.error(
            `Error while handling connection.`,
            error,
          );
        })
        .finally(() => {
          connectionLog.trace(`Purging connection.`);
          allConnections.delete(connectionDone);
        });
    }
  } finally {
    options.signal.removeEventListener("abort", closeListener);
  }

  // Wait for all pending active connections to complete
  await Promise.all([...allConnections]);
}

export async function handleSocksConnection(
  options: CreateSocksServerOptions,
  connection: ConnectionTunnel,
) {
  let workingBuffer = new Uint8Array(0);
  let bufferRequest: SocksHandlerBufferRequest = { timeout: 0, size: 0 };

  options.log.debug(`Creating protocol manager`);

  const hashshakeReader = connection.readable.getReader();
  const handshakeWriter = connection.writable.getWriter();
  const protocolManager = handleProtocol(
    options,
    handshakeWriter,
  );

  let tunnel: ConnectionTunnel | undefined;

  try {
    handshake:
    while (true) {
      while (
        ("size" in bufferRequest)
          ? bufferRequest.size <= workingBuffer.length
          : workingBuffer.indexOf(bufferRequest.until) >= 0
      ) {
        if (options.signal.aborted) {
          options.log.trace(`Listener is aborted, closing.`);
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

      if (options.signal.aborted) {
        options.log.trace(`Listener is aborted, closing.`);
        await protocolManager.return(undefined);
        break handshake;
      }

      const readBuffer = await deadline(
        hashshakeReader.read(),
        bufferRequest.timeout,
        {
          signal: options.signal,
        },
      ).catch((err) => {
        options.log.debug(`Buffer request interrupted.`, err);
        throw err;
      });
      if (readBuffer.done) {
        options.log.debug(`End of stream reached, closing.`);
        return;
      }

      workingBuffer = concatBuffers(
        workingBuffer,
        readBuffer.value,
      );
    }

    hashshakeReader.releaseLock();
    handshakeWriter.releaseLock();

    if (!options.signal.aborted && tunnel) {
      if (workingBuffer?.length) {
        options.log.trace(
          `Writing remaining buffer (${workingBuffer.length} bytes).`,
        );

        const remainingBytesWriter = tunnel.writable.getWriter();
        await remainingBytesWriter.write(workingBuffer);
        remainingBytesWriter.releaseLock();
      }

      options.log.trace(`Piping connection.`);

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
            options.log.error(
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
  writer: { write: (buffer: Uint8Array) => Promise<void> },
): SocksHandler {
  options.log.trace(`handler: Reading socks version.`);

  const { view } = yield {
    timeout: SOCKS_HANDSHAKE_INIT_TIMEOUT,
    size: 1,
    doNotConsume: true,
  };
  const version = view.getUint8(0);

  if (version === Socks4Version) {
    if (options.socks4.enabled) {
      options.log.trace(`handler: Delegate socks4 handler.`);
      return yield* handleSocks4(options, writer);
    } else {
      options.log.trace(`handler: socks4 handler not enabled, closing.`);
      return;
    }
  }

  if (version === Socks5Version) {
    if (options.socks5.enabled) {
      options.log.trace(`handler: Delegate socks5 handler.`);
      return yield* handleSocks5(
        options.socks5,
        options.tunnel,
        writer,
        prefixLogger(options.log, `socks5:`),
      );
    } else {
      options.log.trace(`handler: socks5 handler not enabled, closing.`);
      return;
    }
  }

  options.log.trace(`handler: version (${version}) not supported.`);
}
