import { abortable } from "@std/async/abortable";
import { delay } from "@std/async/delay";

const controller = new AbortController();
controller.signal.onabort = () => {
  console.log("event", controller.signal.reason);
};

abortable(delay(1000), controller.signal)
  .then(() => console.log("resolved"))
  .catch((error) => console.error("errored", error));

console.log("before", controller.signal.reason);

controller.abort("reason 1");
console.log("1", controller.signal.reason);

controller.abort("reason 2");
console.log("2", controller.signal.reason);
