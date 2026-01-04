import { parseArgs } from "@std/cli/parse-args";
import { isValidIP, isValidPort } from "../../common/net.ts";
import { SocksDestinationAddress } from "../../proxy/socks.common.ts";
import { createTunnelRelayClient } from "../../tunnel/client/tunnel.client.ts";
import { TunnelRelayClientProxyDestination } from "../../tunnel/common/tunnel.common.types.ts";
import { TunnelClientError } from "../../tunnel/common/tunnel.errors.ts";
import { CliCommandOptions } from "../cli.types.ts";
import { log } from "node:console";

export async function handleTunnelConnect({
  commandArgs,
  commandLog,
}: CliCommandOptions) {
  commandLog.trace("parsing command args");
  const { _: [endpoint], ...options } = parseArgs(commandArgs, {
    string: [
      "socket-bind",
      "socket-connect",
      "proxy-bind",
      "proxy-connect-mapping",
      "proxy-connect",
      "proxy-connect-host",
      "proxy-connect-port",
    ],
    default: {
      "proxy-connect-host": "127.0.0.1",
      "proxy-connect-port": "1080",
    },
    collect: ["socket-bind", "socket-connect"],
  });

  if (typeof endpoint !== "string") {
    commandLog.error(`url endpoint not specified`);
    return;
  }

  let urlEndpoint: URL;
  try {
    urlEndpoint = new URL(endpoint);
  } catch (err) {
    commandLog.error("invalid url endpoint", err);
    return;
  }

  const controller = new AbortController();

  const interruptListener = () => {
    commandLog.info("[signal]", "Interrupted");
    controller.abort(new TunnelClientError({ reason: "application-aborted" }));
  };
  Deno.addSignalListener("SIGINT", interruptListener);

  try {
    let proxyConnectDestination:
      | ((
        request: SocksDestinationAddress,
      ) => TunnelRelayClientProxyDestination)
      | undefined;
    if (options["proxy-connect-mapping"] && options["proxy-connect"]) {
      commandLog.error(
        `can't define both proxy-connect and proxy-connect-mapping, only one can be used`,
      );
      return;
    }
    if (options["proxy-connect"]) {
      proxyConnectDestination = (request) => ({
        type: "relay",
        service: options["proxy-connect"]!,
        destination: request,
      });
    }
    if (options["proxy-connect-mapping"]) {
      // TODO: Read mapping file and configure destination
    }

    let proxyConnectAddress: Deno.TcpListenOptions | undefined;
    if (proxyConnectDestination) {
      if (!isValidIP(options["proxy-connect-host"].trim())) {
        commandLog.error(`proxy-connect-host must be an IP address`);
        return;
      }

      const parsedPort = isValidPort(options["proxy-connect-port"]);
      if (!parsedPort) {
        commandLog.error(
          `proxy-connect-port must be a number between 1 and 65535`,
        );
        return;
      }

      proxyConnectAddress = {
        hostname: options["proxy-connect-host"].trim(),
        port: parsedPort,
      };
    }

    const binds = options["socket-bind"]
      .map((bind) => {
        const chunks = bind.split("=");
        if (chunks.length !== 2) {
          // TODO: Log
        }

        const service = chunks[0];
        const destination = chunks[1].split(":");
        if (destination.length !== 2) {
          // TODO: log
        }

        const destinationHostname = destination[0];
        const destinationPort = isValidPort(destination[1]);
        if (!destinationPort) {
          // TODO: Log
        }

        return {
          service: service,
          destination: {
            hostname: destinationHostname,
            port: destinationPort,
          } as Omit<Deno.ConnectOptions, "signal">,
        };
      });
    let connectsAbort = false;
    const connects = options["socket-connect"]
      .map((connect) => {
        const chunks = connect.split("=");
        if (chunks.length !== 2) {
          commandLog.error("");
          connectsAbort = true;
        }

        const service = chunks[0];
        const source = chunks[1].split(":");
        if (source.length !== 2) {
          // TODO: log
        }

        const sourceHostname = source[0];
        const sourcePort = isValidPort(source[1]);
        if (!sourcePort) {
          // TODO: Log
        }

        return {
          service: service,
          source: {
            hostname: sourceHostname,
            port: sourcePort,
          } as Deno.TcpListenOptions,
        };
      });

    await createTunnelRelayClient({
      endpoint: urlEndpoint,

      performance: {
        connectionHandleTimeout: 1000,
        decryptQueueSize: 1024,
        reconnectDelay: (context) => 5000, // TODO
      },

      auth: null, // TODO
      log: commandLog,
      signal: controller.signal,

      services: {
        proxyServer: options["proxy-bind"]
          ? { enabled: true, service: options["proxy-bind"] }
          : { enabled: false },
        proxyClient: proxyConnectDestination
          ? {
            enabled: true,
            address: proxyConnectAddress!,
            destination: proxyConnectDestination,
          }
          : { enabled: false },
        bind: binds,
        connect: connects,
      },
    });
  } finally {
    Deno.removeSignalListener("SIGINT", interruptListener);
  }
}
