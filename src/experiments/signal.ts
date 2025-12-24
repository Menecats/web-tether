const controller = new AbortController();
controller.signal.onabort = () => {
  console.log("event", controller.signal.reason);
};

console.log("before", controller.signal.reason);

controller.abort("reason 1");
console.log("1", controller.signal.reason);

controller.abort("reason 2");
console.log("2", controller.signal.reason);
