import { isIPv4, isIPv6 } from "@std/net/unstable-ip";

export function isValidIP(ip: string): 4 | 6 | false {
  if (isIPv4(ip)) return 4;
  if (isIPv6(ip)) return 6;
  return false;
}
export function isValidPort(port: string): number | false {
  if (!/^\s*\d+\s*$/.test(port)) return false;

  const parsed = parseInt(port.trim());
  if (parsed < 1 || parsed > 65535) return false;

  return parsed;
}
