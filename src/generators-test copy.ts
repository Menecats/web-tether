type Yield = string;
type Return = string;
type Next = string;

async function* readBuffer(): AsyncGenerator<Yield, Return, Next> {
  console.log("pre yield 1");
  console.log("got result", yield "first-yield");
  console.log("post yield 1");

  console.log("pre yield 2");
  console.log("got result", yield "second-yield");
  console.log("post yield 2");

  return "return";
}

console.log("pre construction");
const asdf = readBuffer();
console.log("post construction");

let counter = 0;
while (true) {
  const nextValue = `next-${counter++}`;
  console.log(`pre next (${nextValue})`);
  const result = await asdf.next(nextValue);
  console.log(`post next (${nextValue})`);

  console.log(result);
  if (result.done) break;
}

console.log("done");
