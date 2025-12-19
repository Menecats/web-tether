export function ensureLength(
  buffer: BufferSource,
  length: number,
  error: () => unknown,
) {
  if (length > buffer.byteLength) throw error();
}

export function safeReadWithLength8(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 1, error);
  const length = buffer[0];

  ensureLength(buffer, length + 1, error);
  return [buffer.subarray(1, length + 1), length + 1] as const;
}

export function safeReadWithLength16(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 2, error);
  const length = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,
  ).getUint16(0);

  ensureLength(buffer, length + 2, error);
  return [buffer.subarray(2, length + 2), length + 2] as const;
}
export function safeReadWithLength32(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 4, error);
  const length = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,
  ).getUint32(0);

  ensureLength(buffer, length + 4, error);
  return [buffer.subarray(4, length + 4), length + 4] as const;
}

export function safeRead(
  buffer: Uint8Array<ArrayBuffer>,
  length: number,
  error: () => unknown,
) {
  ensureLength(buffer, length, error);
  return [buffer.subarray(0, length), length + 4] as const;
}

export function safeReadUint8(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 1, error);
  return [buffer[0], 1];
}

export function safeReadUint16(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 2, error);
  return [
    new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint16(
      0,
    ),
    2,
  ];
}

export function safeReadUint32(
  buffer: Uint8Array<ArrayBuffer>,
  error: () => unknown,
) {
  ensureLength(buffer, 4, error);
  return [
    new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(
      0,
    ),
    4,
  ];
}

export function writeWithLength16(source: ArrayBuffer) {
  const buffer = new Uint8Array(2 + source.byteLength);
  new DataView(buffer.buffer).setUint16(0, source.byteLength);
  buffer.set(new Uint8Array(source), 2);
  return buffer;
}
