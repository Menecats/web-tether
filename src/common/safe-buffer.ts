export function ensureLength(
  buffer: BufferSource,
  length: number,
  error: () => unknown,
) {
  if (length > buffer.byteLength) throw error();
}

export function encodeUint8(number: number): Uint8Array<ArrayBuffer> {
  const buffer = new Uint8Array(1);
  new DataView(buffer.buffer).setUint8(0, number);
  return buffer;
}
export function encodeUint16(number: number): Uint8Array<ArrayBuffer> {
  const buffer = new Uint8Array(2);
  new DataView(buffer.buffer).setUint16(0, number);
  return buffer;
}
export function encodeUint32(number: number): Uint8Array<ArrayBuffer> {
  const buffer = new Uint8Array(4);
  new DataView(buffer.buffer).setUint32(0, number);
  return buffer;
}

export function encodeWithUint8Length(source: ArrayBuffer): Uint8Array {
  const buffer = new Uint8Array(1 + source.byteLength);
  new DataView(buffer.buffer).setUint8(0, source.byteLength);
  buffer.set(new Uint8Array(source), 1);
  return buffer;
}
export function encodeWithUint16Length(source: ArrayBuffer): Uint8Array {
  const buffer = new Uint8Array(2 + source.byteLength);
  new DataView(buffer.buffer).setUint16(0, source.byteLength);
  buffer.set(new Uint8Array(source), 2);
  return buffer;
}
export function encodeWithUint32Length(source: ArrayBuffer): Uint8Array {
  const buffer = new Uint8Array(4 + source.byteLength);
  new DataView(buffer.buffer).setUint16(0, source.byteLength);
  buffer.set(new Uint8Array(source), 4);
  return buffer;
}

export type ReadOptions = { ahead?: boolean };
export type SafeReader = ReturnType<typeof safeReader>;
export function safeReader(
  source: ArrayBuffer,
  outOfBufferError: () => unknown,
) {
  const buffer = new Uint8Array(source);
  const view = new DataView(source);
  let offset = 0;

  const uint8 = (options?: ReadOptions) => {
    ensureLength(buffer, offset + 1, outOfBufferError);
    const value = view.getUint8(offset);
    if (!options?.ahead) offset += 1;
    return value;
  };
  const uint16 = (options?: ReadOptions) => {
    ensureLength(buffer, offset + 2, outOfBufferError);
    const value = view.getUint16(offset);
    if (!options?.ahead) offset += 2;
    return value;
  };
  const uint32 = (options?: ReadOptions) => {
    ensureLength(buffer, offset + 4, outOfBufferError);
    const value = view.getUint16(offset);
    if (!options?.ahead) offset += 4;
    return value;
  };
  const data = (length: number, options?: ReadOptions) => {
    ensureLength(buffer, offset + length, outOfBufferError);
    const data = buffer.subarray(offset, offset + length);
    if (!options?.ahead) offset += length;
    return data;
  };
  const dataLeft = (options?: ReadOptions) => {
    const data = buffer.subarray(offset);
    if (!options?.ahead) offset += data.length;
    return data;
  };

  return {
    uint8,
    uint16,
    uint32,

    data,
    dataLeft,
  };
}
