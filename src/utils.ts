export function concatBuffers(
  ...buffers: Array<Uint8Array | null | undefined>
) {
  const length = buffers.reduce((t, b) => t + (b?.length ?? 0), 0);
  const result = new Uint8Array(length);

  let offset = 0;
  for (let i = 0; i < buffers.length; ++i) {
    const buffer = buffers[i];
    if (!buffer) continue;

    result.set(buffer, offset);
    offset += buffer.length;
  }
  return result;
}

export function safelyClose(
  closeable: { close(): void } | undefined | null,
) {
  try {
    closeable?.close();
  } catch {
    // Ignore 'close' errors
  }
}

export function printEnum<
  T extends number,
  E extends Record<number, string>,
>(
  e: E,
  k: T,
) {
  return e[k] || `<unknown:${k}>`;
}
