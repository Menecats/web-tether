export async function safeStat(path: string) {
  try {
    return await Deno.stat(path);
  } catch {
    return undefined;
  }
}
