import { printEnum } from "../common/utils.ts";
import { SocksDestinationAddress, SocksHandler } from "./socks.common.ts";
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
  options: CreateSocksServerOptions,
  connection: Deno.TcpConn,
): SocksHandler {
  const { socks5 } = options;
  if (!socks5.enabled) return;

  options.log("trace", `socks5: stage 'handshake'.`);

  const { buffer: [version, methodsCount] } = yield { size: 2 };

  options.log(
    "trace",
    `socks5: got version (${version}) and methods count (${methodsCount}).`,
  );

  if (version !== Socks5Version) {
    options.log("trace", `socks5: invalid version.`);
    return;
  }

  const availableAuthenticationMethods = Array.from(
    (yield { size: methodsCount }).buffer,
  );

  options.log(
    "trace",
    `socks5: got authentication methods: ${
      availableAuthenticationMethods
        .map((m) => printEnum(Socks5Methods, m))
        .join(",")
    }.`,
  );

  options.log(
    "trace",
    `socks5: choosing authentication method given local configuration (enabled: ${socks5.auth.enabled}${
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

  options.log(
    "trace",
    `socks5: authentication method chosen: ${
      printEnum(Socks5Methods, chosenAuthenticationMethod)
    }.`,
  );

  await connection.write(
    new Uint8Array([Socks5Version, chosenAuthenticationMethod]),
  );

  if (chosenAuthenticationMethod === Socks5Methods.NO_ACCEPTABLE_METHODS) {
    options.log(
      "debug",
      `socks5: no available authentication methods found.`,
    );
    return;
  }

  const decoder = new TextDecoder();

  // Auth
  if (chosenAuthenticationMethod === Socks5Methods.USERNAME_PASSWORD) {
    options.log("trace", `socks5: stage 'auth'.`);

    const { buffer: [authenticationVersion, usernameLength] } = yield {
      size: 2,
    };
    options.log(
      "trace",
      `socks5: got authentication version (${authenticationVersion}) and username length.`,
    );
    if (authenticationVersion !== Socks5AuthVersion) {
      options.log(
        "debug",
        `socks5: unsupported authentication version, closing.`,
      );
      return;
    }

    const username = decoder.decode((yield { size: usernameLength }).buffer);
    options.log("trace", `socks5: got username.`);
    const passwordLength = (yield { size: 1 }).buffer[0];
    options.log("trace", `socks5: got password length.`);
    const password = decoder.decode((yield { size: passwordLength }).buffer);
    options.log("trace", `socks5: got password.`);

    options.log("trace", `socks5: validating credentials.`);
    const authenticationResult = (socks5.auth.enabled &&
        await socks5.auth.validate(username, password))
      ? Socks5AuthResult.SUCCESS
      : Socks5AuthResult.FAILURE;

    options.log(
      "trace",
      `socks5: authentication result: ${
        printEnum(Socks5AuthResult, authenticationResult)
      }.`,
    );

    await connection.write(
      new Uint8Array([Socks5AuthVersion, authenticationResult]),
    );
    if (authenticationResult !== Socks5AuthResult.SUCCESS) {
      options.log(
        "debug",
        `socks5: authentication failed, closing.`,
      );
      return;
    }
  }

  options.log("trace", `socks5: stage 'request'.`);

  const { buffer: [requestVersion, command, , addressType] } = yield {
    size: 4,
  };

  options.log(
    "trace",
    `socks5: got version (${requestVersion}), command (${
      printEnum(Socks5Command, command)
    }) and address type (${printEnum(Socks5AddressType, addressType)}).`,
  );

  if (requestVersion !== Socks5Version) {
    options.log("trace", `socks5: invalid version.`);
    return;
  }

  if (command !== Socks5Command.CONNECT) {
    options.log("debug", `socks5: unsupported command.`);
    await connection.write(createResponse(Socks5Reply.COMMAND_NOT_SUPPORTED));
    return;
  }

  let destination: SocksDestinationAddress;

  options.log("trace", `socks5: parsing destination address.`);

  if (addressType === Socks5AddressType.IP_V4) {
    options.log("trace", `socks5: parsing IPv4 address.`);

    const host = Array.from((yield { size: 4 }).buffer).join(".");
    const port = (yield { size: 2 }).view.getUint16(0);

    destination = { mode: "ipv4", host, port };
  } else if (addressType === Socks5AddressType.IP_V6) {
    options.log("trace", `socks5: parsing IPv6 address.`);

    const { view: address } = yield { size: 16 };
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(address.getUint16(i).toString(16));
    }

    const host = parts.join(":");
    const port = (yield { size: 2 }).view.getUint16(0);

    destination = { mode: "ipv6", host, port };
  } else if (addressType === Socks5AddressType.DOMAINNAME) {
    options.log("trace", `socks5: parsing domain name.`);

    const hostLength = (yield { size: 1 }).buffer[0];
    options.log("trace", `socks5: got domain name length (${hostLength}).`);
    const host = decoder.decode((yield { size: hostLength }).buffer);
    const port = (yield { size: 2 }).view.getUint16(0);

    destination = { mode: "domain", host, port };
  } else {
    options.log("debug", `socks5: unsupported address type.`);
    await connection.write(
      createResponse(Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED),
    );
    return;
  }

  options.log(
    "trace",
    `socks5: creating tunnel (${destination.host}:${destination.port}).`,
  );
  const tunnelResponse = await options.tunnel(destination, options.log);

  if (tunnelResponse.ok) {
    options.log(
      "trace",
      `socks5: tunnel created successfully.`,
    );
    await connection.write(createResponse(Socks5Reply.SUCCEEDED));
    return tunnelResponse.tunnel;
  } else {
    options.log(
      "trace",
      `socks5: error creating tunnel (${tunnelResponse.error}).`,
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
    await connection.write(createResponse(reply));
    return undefined;
  }
}
