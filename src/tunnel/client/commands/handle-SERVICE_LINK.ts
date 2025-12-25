import { prefixLogger } from "../../../common/log.ts";
import {
  consumableAsyncQueue,
  deriveSignal,
  printEnum,
  safelyClose,
} from "../../../common/utils.ts";
import {
  RelayCommand,
  RelayLinkReply,
  RelayServiceConnectionReason,
  RelayServiceType,
} from "../../tunnel.relay.ts";
import { handleClientStream } from "../services/handle-stream.ts";
import {
  TunnelClientCommandHandler,
  TunnelClientLink,
} from "../tunnel.client.types.ts";

export const handle_SERVICE_LINK: TunnelClientCommandHandler = (
  { decoder, buffer, write, signal, services, log },
) => {
  const encodedUID = buffer.data(4, { ahead: true });
  const uid = buffer.int32();

  const name = decoder.decode(buffer.data(buffer.uint16()));

  if (uid >= 0 || services.links.has(uid)) {
    log.trace(`recevied link request, but has an invalid identifier`);
    write(
      new Uint8Array([
        RelayCommand.SERVICE_LINK,
        ...encodedUID,
        RelayLinkReply.SERVICE_INVALID_IDENTIFIER,
      ]),
    );
    return;
  }

  const service = services.registered.get(name);
  if (!service) {
    log.trace(`recevied link request, but the service is not known`);
    write(
      new Uint8Array([
        RelayCommand.SERVICE_LINK,
        ...encodedUID,
        RelayLinkReply.SERVICE_NOT_FOUND,
      ]),
    );
    return;
  }

  const serviceLog = prefixLogger(log, `[link:${uid}/${name}]`);
  const serviceAbort = deriveSignal(signal);

  serviceLog.trace(`requested`);

  let destination: Deno.ConnectOptions;
  if (service.type === RelayServiceType.SOCKS_PROXY) {
    const hostname = decoder.decode(buffer.data(buffer.uint16()));
    const port = buffer.uint16();

    destination = { hostname, port, signal: serviceAbort.signal };
  } else {
    destination = { ...service.destination, signal: serviceAbort.signal };
  }

  serviceLog.trace("connecting");

  const { promise: done, resolve: finalize } = Promise.withResolvers<void>();

  const outputQueue = consumableAsyncQueue<Uint8Array<ArrayBuffer>>({ signal });

  const link: TunnelClientLink = {
    uid,
    tunnel: Deno
      .connect(destination)
      .then((connection) => {
        serviceLog.trace("connected");

        write(
          new Uint8Array([
            RelayCommand.SERVICE_LINK,
            ...encodedUID,
            RelayLinkReply.SUCCESS,
          ]),
        );

        handleClientStream({
          uid,
          tunnel: connection,
          write,
          signal: serviceAbort.signal,
          log: serviceLog,
          outputQueue,
        }).finally(finalize);

        return connection;
      })
      .catch((error) => {
        serviceLog.trace("connection failed", error);

        write(
          new Uint8Array([
            RelayCommand.SERVICE_LINK,
            ...encodedUID,
            RelayLinkReply.CONNECT_GENERAL_FAILURE, // TODO: Reason
          ]),
        );

        finalize();

        return undefined;
      }),

    write: (content) => outputQueue.push(content),
    close: (reason) => {
      serviceLog.trace(
        `closing connection with reason: ${
          printEnum(RelayServiceConnectionReason, reason)
        }`,
      );
      finalize();
    },
    done,
  };

  services.links.set(uid, link);
  done.finally(() => {
    services.links.delete(uid);

    serviceAbort.abort();
    link.tunnel.then((c) => safelyClose(c));
  });
};
