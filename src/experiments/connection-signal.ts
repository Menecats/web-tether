const testController = new AbortController();
const testSignal = testController.signal;

setTimeout(() => {
  console.log("aborted");
  testController.abort("abort error");
}, 10);

const connection = await Deno.connect({
  hostname: "www.example.com",
  port: 80,
  signal: testSignal,
});

console.log("connected");

setTimeout(() => {
  console.log("closed");
  connection.close();
}, 150);

const reader = connection.readable.getReader();
try {
  console.log("read", await reader.read());
} catch (err) {
  console.log("err", err);
}
