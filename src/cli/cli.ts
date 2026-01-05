import { ArgumentValue, Command, EnumType, Type } from "@cliffy/command";
import { InvalidTypeError } from "@cliffy/flags";
import { promptSecret } from "@std/cli/prompt-secret";
import * as path from "@std/path";
import { parse } from "@std/yaml/parse";
import { asyncAction } from "../common/async.ts";
import { safeStat } from "../common/fs.ts";
import {
  colorizeOutput,
  createLogger,
  Logger,
  LogLevel,
  LogLevels,
  prefixLogger,
} from "../common/log.ts";
import { isValidIP, isValidPort } from "../common/net.ts";
import { areBuffersEqual } from "../common/safe-buffer.ts";
import {
  exportECDHKeyPair,
  importECDHPrivateKey,
  importECDHPublicKey,
  pbkdf2Hash512,
  pemToBuffer,
} from "../common/security.ts";
import { cancellableAbort } from "../common/utils.ts";
import { SocksDestinationAddress } from "../proxy/socks.common.ts";
import { createTunnelRelayClient } from "../tunnel/client/tunnel.client.ts";
import {
  TunnelRelayClientOptions,
  TunnelRelayClientProxyDestination,
} from "../tunnel/common/tunnel.common.types.ts";
import {
  TunnelClientError,
  TunnelServerError,
} from "../tunnel/common/tunnel.errors.ts";
import { TunnelSecurityPermissions } from "../tunnel/common/tunnel.security.ts";
import { createTunnelRelayServer } from "../tunnel/server/tunnel.server.ts";
import { TunnelRelayPermissionsSchema } from "./command/tunnel-relay.ts";

function configureLogger(
  configLevel: LogLevel,
  output: (...args: unknown[]) => void,
): Logger {
  const allowedLogLevels = LogLevels.slice(LogLevels.indexOf(configLevel));

  const logger = createLogger(
    colorizeOutput(
      output,
      (level: LogLevel) => allowedLogLevels.includes(level),
    ),
  );

  return logger;
}

export class TcpPortType extends Type<number> {
  public parse(type: ArgumentValue): number {
    const port = isValidPort(type.value);
    if (!port) throw new InvalidTypeError(type);

    return port;
  }
}
export class IPAddressType extends Type<string> {
  public parse(type: ArgumentValue): string {
    if (!isValidIP(type.value)) throw new InvalidTypeError(type);
    return type.value.trim();
  }
}

export class WsEndpointType extends Type<URL> {
  public parse(type: ArgumentValue): URL {
    if (!/^wss?:\/\//.test(type.value)) throw new InvalidTypeError(type);

    try {
      return new URL(type.value);
    } catch {
      throw new InvalidTypeError(type);
    }
  }
}
export class SocketBindType
  extends Type<TunnelRelayClientOptions["services"]["bind"][number]> {
  public parse(
    type: ArgumentValue,
  ): TunnelRelayClientOptions["services"]["bind"][number] {
    const chunks = type.value.split("@");
    if (chunks.length !== 2) throw new InvalidTypeError(type);

    const service = chunks[0].trim();
    const rawDestination = chunks[1].trim();

    if (!service || !rawDestination) throw new InvalidTypeError(type);

    const colonIndex = rawDestination.lastIndexOf(":");
    if (colonIndex < 0) throw new InvalidTypeError(type);
    const hostname = rawDestination.substring(0, colonIndex).trim();
    const port = isValidPort(rawDestination.substring(colonIndex + 1));

    if (!hostname || !port) throw new InvalidTypeError(type);

    return {
      service,
      destination: { hostname, port },
    };
  }
}

export class SocketConnectType
  extends Type<TunnelRelayClientOptions["services"]["connect"][number]> {
  public parse(
    type: ArgumentValue,
  ): TunnelRelayClientOptions["services"]["connect"][number] {
    const chunks = type.value.split("@");
    if (chunks.length !== 2) throw new InvalidTypeError(type);

    const rawSource = chunks[0].trim();
    const service = chunks[1].trim();

    if (!service || !rawSource) throw new InvalidTypeError(type);

    const colonIndex = rawSource.lastIndexOf(":");
    const hostname = colonIndex < 0
      ? "127.0.0.1"
      : rawSource.substring(0, colonIndex).trim();
    const port = isValidPort(rawSource.substring(colonIndex + 1));

    if (!isValidIP(hostname) || !port) throw new InvalidTypeError(type);

    return {
      service,
      source: { hostname, port },
    };
  }
}

await new Command()
  .name("web-tether")
  .version("1.0.0-pre.0")
  .description(
    "Create and connect to WebSocket relays to expose or access TCP services securely.",
  )
  .globalType("ws-endpoint", new WsEndpointType())
  .globalType("tcp-port", new TcpPortType())
  .globalType("ip-address", new IPAddressType())
  .globalType("log-level", new EnumType(LogLevels))
  .globalOption("-l, --log-level <level:log-level>", "Set log level.", {
    default: "info",
  })
  /**
   * 'connect' command definition
   */
  .command("connect")
  .description("Connect to a relay and create a local or remote port forward.")
  .arguments("<endpoint:ws-endpoint>")
  .type("socket-bind", new SocketBindType())
  .type("socket-connect", new SocketConnectType())
  .option(
    "--socket-bind <bind:socket-bind>",
    "Binds the specified service on the relay so that any request received by the relay are forwarded to the specified listener. Can be repeated to map multiple services to different listeners.",
    { collect: true },
  )
  .option(
    "--socket-connect <connect:socket-connect>",
    "Create a local listener on the specified address and forwards all connections on the relay to the specified service. Can be repeated to relay connections to multiple services.",
    { collect: true },
  )
  .option(
    "--proxy-bind <service:string>",
    "Handle proxy (SOCKS) requests arriving from the relay on the specified service and forward them to a listener indicated by the proxy request.",
  )
  .option(
    "--proxy-connect-static <service:string>",
    "Run a local SOCKS proxy (SOCKS4/5). Requests received by this local proxy are sent over the relay and delivered to the given service.",
    { conflicts: ["proxy-connect-dynamic"] },
  )
  .option(
    "--proxy-connect-dynamic <mappingFile:file>",
    "Run a local SOCKS proxy (SOCKS4/5). Requests received by this local proxy are routed locally or relayed to a remote service according to the given mapping file.",
    { conflicts: ["proxy-connect-static"] },
  )
  .option(
    "--proxy-connect-host <host:ip-address>",
    "Local host address the SOCKS proxy will bind to for proxy-connect mode",
    { default: "127.0.0.1" },
  )
  .option(
    "--proxy-connect-port <port:tcp-port>",
    "Local TCP port the SOCKS proxy listens on for proxy-connect mode",
    { default: 1080 },
  )
  .option(
    "--auth-identity-private-key <clientPrivateKeyFile:file>",
    "Path to the client's private identity file for key-based authentication. When provided, identity-based auth is used and credential-based options are disallowed.",
    {
      conflicts: ["auth-credentials-identifier", "auth-credentials-passkey"],
      required: true,
    },
  )
  .option(
    "--auth-identity-relay-public-key <relayPublicKeyFile:file>",
    "Path to the relay's public identity file for key-based authentication. When provided, identity-based auth is used and credential-based options are disallowed.",
    {
      conflicts: ["auth-credentials-identifier", "auth-credentials-passkey"],
      depends: ["auth-identity-private-key"],
      required: true,
    },
  )
  .option(
    "--auth-credentials-identifier <identifier:string>",
    "Identifier to present when authenticating with credentials. This value maps to the server-side credential entry and is required for credentials-based auth.",
    {
      conflicts: [
        "auth-identity-private-key",
        "auth-identity-relay-public-key",
      ],
      required: true,
    },
  )
  .option(
    "--auth-credentials-passkey <passkey:string>",
    "Plain-text passkey for credentials authentication. Optional when using credentials; if omitted the CLI will prompt securely for the passkey.",
    {
      conflicts: [
        "auth-identity-private-key",
        "auth-identity-relay-public-key",
      ],
      depends: ["auth-credentials-identifier"],
    },
  )
  .action(async (options, endpoint) => {
    const log = configureLogger(options.logLevel, console.error);

    let auth: TunnelRelayClientOptions["auth"];

    const setupLog_auth = prefixLogger(log, "[setup]", "[auth]");
    setupLog_auth.info("Configuring authentication");
    if (options.authCredentialsIdentifier) {
      setupLog_auth.trace("using 'credentials' mode");

      const identifier = options.authCredentialsIdentifier;

      log.trace("requesting passkey (from input or secure prompt)");
      const passkey = options.authCredentialsPasskey ||
        promptSecret("Passkey:");
      if (!passkey) {
        log.error("Passkey is required to use credentials authentication");
        return;
      }

      auth = {
        mode: "credentials",
        identifier,
        passkey,
      };
    } else if (options.authIdentityPrivateKey) {
      setupLog_auth.trace("using 'identity' mode");

      const localPrivateKeyFile = options.authIdentityPrivateKey;
      const relayPublicKeyFile = options.authIdentityRelayPublicKey!;

      setupLog_auth.trace(`checking local private key file existence`);
      if (!await safeStat(localPrivateKeyFile)) {
        setupLog_auth.error(
          `Identity private key file '${localPrivateKeyFile}' not found.`,
        );
        return;
      }

      setupLog_auth.trace(`checking relay public key file existence`);
      if (!await safeStat(relayPublicKeyFile)) {
        setupLog_auth.error(
          `Relay public key file '${relayPublicKeyFile}' not found.`,
        );
        return;
      }

      setupLog_auth.trace(`reading identity private key file`);
      const privateKey = await Deno.readTextFile(localPrivateKeyFile);

      setupLog_auth.trace(`parsing PEM-formatted key`);
      const privateKeyBuffer = pemToBuffer(privateKey);
      if (!privateKeyBuffer) {
        setupLog_auth.error(`Invalid key content: not in PEM format.`);
        return;
      }
      if (privateKeyBuffer.format !== "pkcs8") {
        setupLog_auth.error(
          `Invalid key content: expected a private key (PKCS8).`,
        );
        return;
      }

      let localPrivateKey: CryptoKeyPair;
      try {
        setupLog_auth.trace(`importing ECDH private key`);
        localPrivateKey = await importECDHPrivateKey(privateKeyBuffer.buffer);
      } catch (err) {
        setupLog_auth.error(`Failed to import private key:`, err);
        return;
      }

      setupLog_auth.trace(`reading relay public key file`);
      const publicKey = await Deno.readTextFile(relayPublicKeyFile);

      setupLog_auth.trace(`parsing base64-formatted key`);
      let publicKeyBuffer: Uint8Array<ArrayBuffer>;
      try {
        publicKeyBuffer = Uint8Array.fromBase64(publicKey.trim());
      } catch (err) {
        setupLog_auth.error(`Invalid key content: not in base64 format.`, err);
        return;
      }

      let relayPublicKey: CryptoKey;
      try {
        setupLog_auth.trace(`importing ECDH public key`);
        relayPublicKey = await importECDHPublicKey(publicKeyBuffer);
      } catch (err) {
        setupLog_auth.error(`Failed to import public key:`, err);
        return;
      }

      auth = {
        mode: "identity",
        clientKeys: localPrivateKey,
        serverKey: relayPublicKey,
      };
    } else {
      setupLog_auth.error(`Invalid auth options provided`);
      return;
    }

    const controller = new AbortController();

    const interruptListener = () => {
      prefixLogger(log, "[signal]").info("Interrupt received, shutting down");
      controller.abort(
        new TunnelClientError({ reason: "application-aborted" }),
      );
    };
    Deno.addSignalListener("SIGINT", interruptListener);

    try {
      const setupLog_proxyConnect = prefixLogger(
        log,
        "[setup]",
        "[proxy-connect]",
      );
      let proxyConnectDestination:
        | ((
          request: SocksDestinationAddress,
        ) => TunnelRelayClientProxyDestination)
        | undefined;
      if (options.proxyConnectStatic) {
        setupLog_proxyConnect.trace(
          `configuring static proxy connect to service '${options.proxyConnectStatic}'`,
        );
        proxyConnectDestination = (request) => ({
          type: "relay",
          service: options.proxyConnectStatic!,
          destination: request,
        });
      }
      if (options.proxyConnectDynamic) {
        setupLog_proxyConnect.trace(
          `configuring dynamic proxy connect to service from file '${options.proxyConnectDynamic}'`,
        );

        let proxyConfiguration: undefined | {
          default:
            | { type: "abort" | "local" }
            | { type: "relay"; service: string };
          routes: {
            destination: string;
            route:
              | { type: "local"; remap?: string }
              | { type: "relay"; remap?: string; service: string };
          }[];
        };
        const readProxyMapping = async (): Promise<boolean> => {
          const readLog = prefixLogger(setupLog_proxyConnect, "[read]");
          readLog.trace("checking config file existance");
          const stat = await safeStat(options.proxyConnectDynamic!);
          if (!stat) {
            proxyConfiguration = undefined;
            readLog.warn(
              `Configuration file '${options.proxyConnectDynamic}' not found: proxy won't work.`,
            );
            return false;
          }

          try {
            readLog.trace("reading config file");
            const content = await Deno.readTextFile(
              options.proxyConnectDynamic!,
            );

            readLog.trace("parsing routes");
            const rows = content
              .split("\n")
              .map((row, index) => ({ content: row.trim(), row: index + 1 }))
              .filter((row) => !!row.content && !row.content.startsWith("#"));

            let defaultRoute: Exclude<
              typeof proxyConfiguration,
              undefined
            >["default"] = { type: "abort" };
            const routes: Exclude<
              typeof proxyConfiguration,
              undefined
            >["routes"] = [];

            for (const { content, row } of rows) {
              const chunks = content.split(/\s+/);

              const destination = chunks[0];
              const service = chunks[2];
              const isRemap = chunks[3] === "remap";
              const remap = isRemap && chunks[4] || undefined;

              const isDefault = destination === "default";
              const isLocal = service === "@local";

              if (
                chunks[1] !== "via" ||
                (chunks.length !== 3 && chunks.length !== 5) ||
                (chunks.length === 5 && (isDefault || !isRemap))
              ) {
                readLog.warn(`Invalid config row #${row}`);
                continue;
              }

              if (isDefault) {
                defaultRoute = isLocal
                  ? { type: "local" }
                  : { type: "relay", service };
              } else {
                routes.push({
                  destination,
                  route: isLocal
                    ? { type: "local", remap }
                    : { type: "relay", remap, service },
                });
              }
            }

            if (defaultRoute.type === "abort") {
              readLog.warn(
                "no default route set, non-defined routes will be aborted",
              );
            }

            proxyConfiguration = { default: defaultRoute, routes };

            readLog.trace("routes loaded", proxyConfiguration);

            return true;
          } catch (err) {
            readLog.error(
              `Failed to read or parse config file '${options.proxyConnectDynamic}': proxy won't work.`,
              err,
            );
            proxyConfiguration = undefined;
            return false;
          }
        };

        if (!await readProxyMapping()) {
          setupLog_proxyConnect.error(`Unable to parse config file.`);
          return;
        }

        asyncAction(async (watcherSignal) => {
          const watcherLog = prefixLogger(setupLog_proxyConnect, "[watch]");
          watcherLog.info("starting proxy configuration file watcher");

          const watcher = Deno.watchFs(options.proxyConnectDynamic!);
          const aborter = cancellableAbort(
            watcherSignal,
            () => watcher.close(),
          );

          try {
            for await (const event of watcher) {
              if (event.kind === "access") continue;

              watcherLog.trace(
                "dynamic proxy configuration file changed, reloading",
                event,
              );
              await readProxyMapping();
            }
          } finally {
            aborter.cancel();
            watcherLog.trace("stopped watching proxy configuration file");
          }
        }, controller);

        proxyConnectDestination = (request) => {
          if (!proxyConfiguration) return { type: "abort" };

          const route = proxyConfiguration.routes
            .find((r) => r.destination === request.host);

          if (route) {
            if (route.route.type === "relay") {
              return {
                type: "relay",
                service: route.route.service,
                destination: {
                  host: route.route.remap || request.host,
                  port: request.port,
                },
              };
            }

            return {
              type: "local",
              destination: {
                host: route.route.remap || request.host,
                port: request.port,
              },
            };
          }

          const defaultRoute = proxyConfiguration.default;
          if (defaultRoute.type === "relay") {
            return {
              type: "relay",
              service: defaultRoute.service,
              destination: request,
            };
          }

          if (defaultRoute.type === "local") {
            return { type: "local", destination: request };
          }

          return { type: "abort" };
        };
      }

      await createTunnelRelayClient({
        endpoint: endpoint,

        performance: {
          connectionHandleTimeout: 1000,
          decryptQueueSize: 1024,
          reconnectDelay: (context) => 5000, // TODO
        },

        auth,
        log,
        signal: controller.signal,

        services: {
          proxyServer: options.proxyBind
            ? { enabled: true, service: options.proxyBind }
            : { enabled: false },
          proxyClient: proxyConnectDestination
            ? {
              enabled: true,
              address: {
                hostname: options.proxyConnectHost,
                port: options.proxyConnectPort,
              },
              destination: proxyConnectDestination,
            }
            : { enabled: false },
          bind: options.socketBind || [],
          connect: options.socketConnect || [],
        },
      });
    } finally {
      Deno.removeSignalListener("SIGINT", interruptListener);
      controller.abort(
        new TunnelClientError({ reason: "application-aborted" }),
      );
    }
  })
  /**
   * 'relay' command definition
   */
  .command("relay")
  .description(
    "Run a relay server (WebSocket endpoint) to bridge TCP connections",
  )
  .option(
    "-c, --clients <clientsFile:file>",
    "Path to the clients configuration file that defines authorized clients and their permissions.",
    { required: true },
  )
  .option(
    "-i, --identity <identityFile:file>",
    "Path to the relay's private identity file. If omitted, identity-based client authentication will be disabled.",
  )
  .option(
    "-h, --host <host:ip-address>",
    "Host address the relay will bind to for incoming WebSocket connections.",
    { default: "0.0.0.0" },
  )
  .option(
    "-p, --port <port:tcp-port>",
    "TCP port on which the relay will listen for WebSocket connections",
    { default: 3000 },
  )
  .action(async (options) => {
    const log = configureLogger(options.logLevel, console.error);

    const setupLog_identity = prefixLogger(log, "[setup]", "[identity]");

    let relayIdentity: CryptoKeyPair | undefined;
    if (!options.identity) {
      setupLog_identity.warn(
        "No identity file provided, identity-based client authentication will be disabled.",
      );
    } else {
      setupLog_identity.trace(`checking identity file existence`);
      const stat = await safeStat(options.identity);
      if (!stat) {
        setupLog_identity.error(
          `Identity file '${options.identity}' not found.`,
        );
        return;
      }

      setupLog_identity.trace(`reading identity file`);
      const privateKey = await Deno.readTextFile(options.identity);

      setupLog_identity.trace(`parsing PEM-formatted key`);
      const privateKeyBuffer = pemToBuffer(privateKey);
      if (!privateKeyBuffer) {
        setupLog_identity.error(`Invalid key content: not in PEM format.`);
        return;
      }
      if (privateKeyBuffer.format !== "pkcs8") {
        setupLog_identity.error(
          `Invalid key content: expected a private key (PKCS8).`,
        );
        return;
      }

      try {
        setupLog_identity.trace(`importing ECDH private key`);
        relayIdentity = await importECDHPrivateKey(privateKeyBuffer.buffer);
      } catch (err) {
        setupLog_identity.error(`Failed to import private key:`, err);
        return;
      }
    }

    const setupLog_clients = prefixLogger(log, "[setup]", "[clients]");

    let relayPermissions: TunnelRelayPermissionsSchema | undefined;
    async function readPermissions(): Promise<boolean> {
      setupLog_clients.trace("checking clients file existance");
      const stat = await safeStat(options.clients);
      if (!stat) {
        relayPermissions = undefined;
        setupLog_clients.warn(
          `Clients file '${options.clients}' not found: no clients will be authorized.`,
        );
        return false;
      }

      try {
        setupLog_clients.trace("reading clients file");
        const content = await Deno.readTextFile(options.clients);
        let decoded: unknown = undefined;
        try {
          setupLog_clients.trace("attempting JSON parse");
          decoded = JSON.parse(content);
        } catch (jsonErr) {
          try {
            decoded = parse(content);

            // Out of order logging to make more sens in error logging
            setupLog_clients.trace("JSON parse failed");

            setupLog_clients.trace("attempting YAML parse");
          } catch (yamlErr) {
            setupLog_clients.trace("JSON parse failed", jsonErr);

            setupLog_clients.trace("attempting YAML parse");
            setupLog_clients.trace("YAML parse failed", yamlErr);
          }
        }

        if (!decoded) throw "Content is neither JSON nor YAML";

        setupLog_clients.trace("validating clients configuration");

        relayPermissions = await TunnelRelayPermissionsSchema.parseAsync(
          decoded,
        );

        // TODO: Validate duplicate client identifiers / missing bindings / etc..

        setupLog_clients.trace("clients configuration loaded successfully");
        return true;
      } catch (err) {
        setupLog_clients.error(
          `Failed to read or parse clients file '${options.clients}': clients will not be authorized.`,
          err,
        );
        relayPermissions = undefined;
        return false;
      }
    }

    if (!await readPermissions()) {
      setupLog_clients.error(`Unable to parse clients file.`);
      return;
    }

    const controller = new AbortController();

    asyncAction(async (watcherSignal) => {
      const watcherLog = prefixLogger(setupLog_clients, "[watch]");
      watcherLog.info("starting clients file watcher");

      const watcher = Deno.watchFs(options.clients);
      const aborter = cancellableAbort(watcherSignal, () => watcher.close());

      try {
        for await (const event of watcher) {
          if (event.kind === "access") continue;

          watcherLog.trace("clients file changed, reloading", event);
          await readPermissions();
        }
      } finally {
        aborter.cancel();
        watcherLog.trace("stopped watching clients file");
      }
    }, controller);

    const interruptListener = () => {
      prefixLogger(log, ["signal"]).info("Interrupt received, shutting down");
      controller.abort(
        new TunnelServerError({ reason: "application-aborted" }),
      );
    };
    Deno.addSignalListener("SIGINT", interruptListener);

    try {
      await createTunnelRelayServer({
        listen: { hostname: options.host, port: options.port },
        performance: { decryptQueueSize: 1024 },
        auth: {
          credentials: {
            enabled: true,
            lookup: (identifier) => {
              if (!relayPermissions) return undefined;

              const client = relayPermissions.clients.find((c) =>
                c.auth.mode === "credentials" &&
                c.auth.identifier === identifier
              );
              if (!client || client.auth.mode !== "credentials") {
                return undefined;
              }

              return {
                salt: client.auth.credentials.salt,
                hash: client.auth.credentials.hash,
                permissions: {
                  bind: !client.permissions.some((p) => p.type === "bind")
                    ? { enabled: false }
                    : {
                      enabled: true,
                      allowed: (service: string) =>
                        client.permissions.some((p) =>
                          p.type === "bind" && p.service(service)
                        ),
                    },
                  connect: !client.permissions.some((p) => p.type === "connect")
                    ? { enabled: false }
                    : {
                      enabled: true,
                      allowed: (service: string) =>
                        client.permissions.some((p) =>
                          p.type === "connect" && p.service(service)
                        ),
                    },
                } satisfies TunnelSecurityPermissions,
              };
            },
          },
          identity: !relayIdentity ? { enabled: false } : {
            enabled: true,
            serverKeys: relayIdentity,
            lookupClient: (hash) => {
              if (!relayPermissions) return undefined;

              const client = relayPermissions.clients.find((c) =>
                c.auth.mode === "identity" && areBuffersEqual(hash, c.auth.hash)
              );
              if (!client || client.auth.mode !== "identity") return undefined;

              return {
                key: client.auth.publicKey,
                permissions: {
                  bind: !client.permissions.some((p) => p.type === "bind")
                    ? { enabled: false }
                    : {
                      enabled: true,
                      allowed: (service: string) =>
                        client.permissions.some((p) =>
                          p.type === "bind" && p.service(service)
                        ),
                    },
                  connect: !client.permissions.some((p) => p.type === "connect")
                    ? { enabled: false }
                    : {
                      enabled: true,
                      allowed: (service: string) =>
                        client.permissions.some((p) =>
                          p.type === "connect" && p.service(service)
                        ),
                    },
                } satisfies TunnelSecurityPermissions,
              };
            },
          },
        },
        log,
        signal: controller.signal,
      });
    } finally {
      Deno.removeSignalListener("SIGINT", interruptListener);
      controller.abort(
        new TunnelServerError({ reason: "application-aborted" }),
      );
    }
  })
  /**
   * 'generate-identity' command definition
   */
  .command("generate-identity")
  .description(
    "Create a client identity (public/private keypair). Outputs a private key file and a corresponding public key.",
  )
  .option(
    "-i, --identity-file <identityFile:file>",
    "File path where the generated client identity (private key and associated public key) will be saved. If the file already exists the command will fail.",
    { required: true },
  )
  .action(async (options) => {
    const log = configureLogger(options.logLevel, console.error);

    log.trace("generating and exporting ECDH key pair");
    const pair = await exportECDHKeyPair();

    log.trace("normalizing identity file path");
    const privateIdentityFile = path.normalize(options.identityFile);
    const publicIdentityFile = privateIdentityFile + ".pub";

    log.trace(`  private: '${privateIdentityFile}'`);
    log.trace(`  public : '${publicIdentityFile}'`);

    log.trace("ensuring private key file does not end with '.pub'");
    if (privateIdentityFile.endsWith(".pub")) {
      log.error("Identity file must not end with '.pub'");
      return;
    }

    const privateIdentityStat = await safeStat(privateIdentityFile);
    const publicIdentityStat = await safeStat(publicIdentityFile);

    if (privateIdentityStat) {
      log.error(
        `Found existing private key at '${privateIdentityFile}'. Remove it or choose a different name and try again.'`,
      );
    }
    if (publicIdentityStat) {
      log.error(
        `Found existing public key at '${publicIdentityFile}'. Remove it or choose a different name and try again.`,
      );
    }
    if (privateIdentityStat || publicIdentityStat) return;

    log.trace(`writing private key file at '${privateIdentityFile}'`);
    await Deno.writeTextFile(
      privateIdentityFile,
      pair.privateKey.content.encoded,
    );

    log.trace(`writing public key file at '${publicIdentityFile}'`);
    await Deno.writeTextFile(
      publicIdentityFile,
      pair.publicKey.content.decoded.toBase64(),
    );

    log.info(
      `Identity '${privateIdentityFile}' generated successfully.`,
    );
  })
  /**
   * 'generate-credentials' command definition
   */
  .command("generate-credentials")
  .description(
    "Generate server credentials: produce a salted, securely hashed password string to store on the relay for authenticating clients.",
  )
  .option(
    "-i, --identifier <identifier:string>",
    "Human-readable ID or label associated with the generated credential (e.g., username, client-name, etc.). Stored with the hashed credential for lookup.",
    { required: true },
  )
  .option(
    "-p, --passkey <passkey:string>",
    "Plain-text password to hash for server credential generation. If omitted, the command will prompt securely for the password.",
  )
  .action(async (options) => {
    const log = configureLogger(options.logLevel, console.error);

    log.trace("validating identifier characters");
    if (!/^[a-zA-Z0-9.\-_]+$/.test(options.identifier)) {
      log.error(
        "Identifier may contain only letters, numbers, and these characters: `.`, `-`, `_`",
      );
      return;
    }

    log.trace("requesting passkey (from input or secure prompt)");
    const passkey = options.passkey || promptSecret("Passkey:");
    if (!passkey) {
      log.error("Passkey is required to generate credentials");
      return;
    }

    log.trace("generating cryptographic salt (16 bytes)");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    log.debug("generated salt (raw bytes):", salt);

    log.trace("encoding passkey to UTF-8 bytes");
    const encodedPasskey = new TextEncoder().encode(passkey);

    log.trace("deriving hashed passkey using PBKDF2-SHA512");
    const hashedPasskey = new Uint8Array(
      await pbkdf2Hash512(encodedPasskey, salt),
    );

    log.trace("outputting credential record");
    console.log(
      `credentials:${options.identifier}:${salt.toBase64()}|${hashedPasskey.toBase64()}`,
    );
  })
  /**
   * Run the command
   */
  .parse(Deno.args);
