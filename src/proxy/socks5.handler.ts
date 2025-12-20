import { Logger } from "../common/log.ts";
import { printEnum } from "../common/utils.ts";
import {
  SOCKS_AUTH_INIT_TIMEOUT,
  SOCKS_AUTH_TIMEOUT,
  SOCKS_HANDSHAKE_TIMEOUT,
  SOCKS_REQUEST_INIT_TIMEOUT,
  SOCKS_REQUEST_TIMEOUT,
  SocksDestinationAddress,
  SocksHandler,
} from "./socks.common.ts";
import { CreateSocksServerOptions } from "./socks.server.ts";

export const Socks5Version = 0x05;

enum Socks5Methods {
  NO_AUTHENTICATION_REQUIRED = 0x00,
  GSSAPI = 0x01,
  USERNAME_PASSWORD = 0x02,
  // IANA_ASSIGNED = 0x03 -> 0x7F,
  // RESERVED_FOR_PRIVATE_METHODS = 0x80 -> 0xFE,
  NO_ACCEPTABLE_METHODS = 0xFF,
}
enum Socks5Command {
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03,
}
enum Socks5AddressType {
  IP_V4 = 0x01,
  DOMAINNAME = 0x03,
  IP_V6 = 0x04,
}
enum Socks5Reply {
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

const Socks5AuthVersion = 0x01;
enum Socks5AuthResult {
  SUCCESS = 0x00,
  FAILURE = 0x01,
}

function createResponse(reply: Socks5Reply) {
  return new Uint8Array([
    Socks5Version,
    reply,
    0x00,
    Socks5AddressType.IP_V4,
    // Host
    0x00,
    0x00,
    0x00,
    0x00,
    // Port
    0x00,
    0x00,
  ]);
}

export async function* handleSocks5(
  socks5: CreateSocksServerOptions["socks5"] & { enabled: true },
  createTunnel: CreateSocksServerOptions["tunnel"],
  writer: { write: (buffer: Uint8Array) => Promise<void> },
  log: Logger,
): SocksHandler {
  log.trace(`stage 'handshake'.`);

  const { buffer: [version, methodsCount] } = yield {
    timeout: SOCKS_HANDSHAKE_TIMEOUT,
    size: 2,
  };

  log.trace(
    `got version (${version}) and methods count (${methodsCount}).`,
  );

  if (version !== Socks5Version) {
    log.trace(`invalid version.`);
    return;
  }

  const availableAuthenticationMethods = Array.from(
    (yield { timeout: SOCKS_HANDSHAKE_TIMEOUT, size: methodsCount }).buffer,
  );

  log.trace(
    `got authentication methods: ${
      availableAuthenticationMethods
        .map((m) => printEnum(Socks5Methods, m))
        .join(",")
    }.`,
  );

  log.trace(
    `choosing authentication method given local configuration (enabled: ${socks5.auth.enabled}${
      socks5.auth.enabled ? `, required: ${socks5.auth.required}` : ""
    }).`,
  );

  let chosenAuthenticationMethod = Socks5Methods.NO_ACCEPTABLE_METHODS;
  if (
    socks5.auth.enabled &&
    availableAuthenticationMethods.includes(
      Socks5Methods.USERNAME_PASSWORD,
    )
  ) {
    chosenAuthenticationMethod = Socks5Methods.USERNAME_PASSWORD;
  } else if (
    (!socks5.auth.enabled || !socks5.auth.required) &&
    availableAuthenticationMethods.includes(
      Socks5Methods.NO_AUTHENTICATION_REQUIRED,
    )
  ) {
    chosenAuthenticationMethod = Socks5Methods.NO_AUTHENTICATION_REQUIRED;
  }

  log.trace(
    `authentication method chosen: ${
      printEnum(Socks5Methods, chosenAuthenticationMethod)
    }.`,
  );

  await writer.write(
    new Uint8Array([Socks5Version, chosenAuthenticationMethod]),
  );

  if (chosenAuthenticationMethod === Socks5Methods.NO_ACCEPTABLE_METHODS) {
    log.debug(
      `no available authentication methods found.`,
    );
    return;
  }

  const decoder = new TextDecoder();

  // Auth
  if (chosenAuthenticationMethod === Socks5Methods.USERNAME_PASSWORD) {
    log.trace(`stage 'auth'.`);

    const { buffer: [authenticationVersion, usernameLength] } = yield {
      timeout: SOCKS_AUTH_INIT_TIMEOUT,
      size: 2,
    };
    log.trace(
      `got authentication version (${authenticationVersion}) and username length.`,
    );
    if (authenticationVersion !== Socks5AuthVersion) {
      log.debug(
        `unsupported authentication version, closing.`,
      );
      return;
    }

    const username = decoder.decode(
      (yield { timeout: SOCKS_AUTH_TIMEOUT, size: usernameLength }).buffer,
    );
    log.trace(`got username.`);
    const passwordLength =
      (yield { timeout: SOCKS_AUTH_TIMEOUT, size: 1 }).buffer[0];
    log.trace(`got password length.`);
    const password = decoder.decode(
      (yield { timeout: SOCKS_AUTH_TIMEOUT, size: passwordLength }).buffer,
    );
    log.trace(`got password.`);

    log.trace(`validating credentials.`);
    const authenticationResult = (socks5.auth.enabled &&
        await socks5.auth.validate(username, password))
      ? Socks5AuthResult.SUCCESS
      : Socks5AuthResult.FAILURE;

    log.trace(
      `authentication result: ${
        printEnum(Socks5AuthResult, authenticationResult)
      }.`,
    );

    await writer.write(
      new Uint8Array([Socks5AuthVersion, authenticationResult]),
    );
    if (authenticationResult !== Socks5AuthResult.SUCCESS) {
      log.debug(
        `authentication failed, closing.`,
      );
      return;
    }
  }

  log.trace(`stage 'request'.`);

  const { buffer: [requestVersion, command, , addressType] } = yield {
    timeout: SOCKS_REQUEST_INIT_TIMEOUT,
    size: 4,
  };

  log.trace(
    `got version (${requestVersion}), command (${
      printEnum(Socks5Command, command)
    }) and address type (${printEnum(Socks5AddressType, addressType)}).`,
  );

  if (requestVersion !== Socks5Version) {
    log.trace(`invalid version.`);
    return;
  }

  if (command !== Socks5Command.CONNECT) {
    log.debug(`unsupported command.`);
    await writer.write(createResponse(Socks5Reply.COMMAND_NOT_SUPPORTED));
    return;
  }

  let destination: SocksDestinationAddress;

  log.trace(`parsing destination address.`);

  if (addressType === Socks5AddressType.IP_V4) {
    log.trace(`parsing IPv4 address.`);

    const host = Array.from(
      (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: 4 }).buffer,
    ).join(".");
    const port = (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: 2 }).view
      .getUint16(0);

    destination = { mode: "ipv4", host, port };
  } else if (addressType === Socks5AddressType.IP_V6) {
    log.trace(`parsing IPv6 address.`);

    const { view: address } = yield {
      timeout: SOCKS_REQUEST_TIMEOUT,
      size: 16,
    };
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(address.getUint16(i).toString(16));
    }

    const host = parts.join(":");
    const port = (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: 2 }).view
      .getUint16(0);

    destination = { mode: "ipv6", host, port };
  } else if (addressType === Socks5AddressType.DOMAINNAME) {
    log.trace(`parsing domain name.`);

    const hostLength =
      (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: 1 }).buffer[0];
    log.trace(`got domain name length (${hostLength}).`);
    const host = decoder.decode(
      (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: hostLength }).buffer,
    );
    const port = (yield { timeout: SOCKS_REQUEST_TIMEOUT, size: 2 }).view
      .getUint16(0);

    destination = { mode: "domain", host, port };
  } else {
    log.debug(`unsupported address type.`);
    await writer.write(
      createResponse(Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED),
    );
    return;
  }

  log.trace(
    `creating tunnel (${destination.host}:${destination.port}).`,
  );
  const tunnelResponse = await createTunnel(destination, log);

  if (tunnelResponse.ok) {
    log.trace(
      `tunnel created successfully.`,
    );
    await writer.write(createResponse(Socks5Reply.SUCCEEDED));
    return tunnelResponse.tunnel;
  } else {
    log.trace(
      `error creating tunnel (${tunnelResponse.error}).`,
    );
    let reply: Socks5Reply;
    switch (tunnelResponse.error) {
      case "not-allowed":
        reply = Socks5Reply.CONNECTION_NOT_ALLOWED_BY_RULESET;
        break;
      case "network-unreachable":
        reply = Socks5Reply.NETWORK_UNREACHABLE;
        break;
      case "host-unreachable":
        reply = Socks5Reply.HOST_UNREACHABLE;
        break;
      case "connection-refused":
        reply = Socks5Reply.CONNECTION_REFUSED;
        break;
      case "ttl-expired":
        reply = Socks5Reply.TTL_EXPIRED;
        break;
      default:
        reply = Socks5Reply.GENERAL_SOCKS_SERVER_FAILURE;
        break;
    }
    await writer.write(createResponse(reply));
    return undefined;
  }
}
