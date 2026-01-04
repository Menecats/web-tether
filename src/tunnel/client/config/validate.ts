import { verifyCryptoKeyPair } from "../../../common/security.ts";
import { TunnelRelayClientOptions } from "../../common/tunnel.common.types.ts";
import { TunnelClientError } from "../../common/tunnel.errors.ts";

export async function validateTunnelClientConfiguration(
  options: TunnelRelayClientOptions,
) {
  if (options.auth.mode === "identity") {
    const valid = await verifyCryptoKeyPair(
      options.auth.clientKeys,
    );
    if (!valid) {
      throw new TunnelClientError({
        reason: "invalid-configuration",
        details: "client-keys",
      });
    }
  }

  const boundServices: string[] = [
    options.services.proxyServer.enabled
      ? [options.services.proxyServer.service]
      : [],
    options.services.bind.map((v) => v.service),
  ].flat();
  const duplicateServices = [
    ...boundServices
      .reduce<Map<string, number>>((accumulated, service) => {
        accumulated.set(service, (accumulated.get(service) || 0) + 1);
        return accumulated;
      }, new Map())
      .entries(),
  ].filter(([, count]) => count > 1).map(([service]) => service);
  if (duplicateServices.length) {
    throw new TunnelClientError({
      reason: "invalid-configuration",
      details: "duplicate-bound-services",
    });
  }

  const boundAddresses: Deno.TcpListenOptions[] = [
    options.services.proxyClient.enabled
      ? [options.services.proxyClient.address]
      : [],
    options.services.connect.map((c) => c.source),
  ].flat();
  const duplicatePorts = [
    ...boundAddresses
      .reduce<Map<number, number>>(
        (accumulated, address) => {
          accumulated.set(
            address.port,
            (accumulated.get(address.port) || 0) + 1,
          );
          return accumulated;
        },
        new Map(),
      )
      .entries(),
  ].filter(([, count]) => count > 1).map(([port]) => port);
  if (duplicatePorts.length) {
    throw new TunnelClientError({
      reason: "invalid-configuration",
      details: "duplicate-bound-addresses",
    });
  }
}
