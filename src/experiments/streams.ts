const readable = new ReadableStream<Uint8Array<ArrayBuffer>>({
  type: "bytes",
  start: (controller) => {},
  pull: (controller) => {},
  cancel: () => {},
});

const writable = new WritableStream<Uint8Array<ArrayBufferLike>>({
  start: (controller) => {},
  write: (chunk, controller) => {},
  abort: (reason) => {},
  close: () => {},
});
