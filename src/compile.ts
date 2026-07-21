import version from "./version.json" with { type: "json" };

interface CompileTarget {
  /** The target passed to `deno compile --target`. */
  target: string;
  /** The platform suffix used in the output file name. */
  suffix: string;
}

const targets: Record<string, CompileTarget> = {
  "darwin:aarch64": {
    target: "aarch64-apple-darwin",
    suffix: "darwin_aarch64",
  },
  "darwin:amd64": {
    target: "x86_64-apple-darwin",
    suffix: "darwin_amd64",
  },
  "linux:aarch64": {
    target: "aarch64-unknown-linux-gnu",
    suffix: "linux_aarch64",
  },
  "linux:amd64": {
    target: "x86_64-unknown-linux-gnu",
    suffix: "linux_amd64",
  },
  "win:aarch64": {
    target: "aarch64-pc-windows-msvc",
    suffix: "win_aarch64",
  },
  "win:amd64": {
    target: "x86_64-pc-windows-msvc",
    suffix: "win_amd64",
  },
};

const selected = Deno.args[0];
const entries = selected
  ? [[selected, targets[selected]] as const]
  : Object.entries(targets);

for (const [key, info] of entries) {
  if (!info) {
    console.error(
      `Unknown target: ${key}. Available targets: ${
        Object.keys(targets).join(", ")
      }.`,
    );
    Deno.exit(1);
  }

  const output = `./dist/web-tether_${version}_${info.suffix}`;
  console.log(`Compiling ${key} (v${version}) -> ${output}`);

  const command = new Deno.Command("deno", {
    args: [
      "compile",
      "--target",
      info.target,
      "-o",
      output,
      "--no-check",
      "-A",
      "./dist/web-tether.js",
    ],
    stdout: "inherit",
    stderr: "inherit",
  });

  const { code } = await command.output();
  if (code !== 0) {
    Deno.exit(code);
  }
}
