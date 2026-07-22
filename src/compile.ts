import version from "./version.json" with { type: "json" };

const dist = `./dist`;
const bundledScript = `${dist}/web-tether_${version}.js`;

async function bundle() {
  const command = new Deno.Command("deno", {
    args: [
      "bundle",
      "-o",
      bundledScript,
      "./src/cli/cli.ts",
    ],
    stdout: "inherit",
    stderr: "inherit",
  });
  const { code: code } = await command.output();
  if (code !== 0) Deno.exit(code);
}

async function compile() {
  const targets: Record<string, { target: string; suffix: string }> = {
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

  for (const [key, info] of Object.entries(targets)) {
    const output = `${dist}/web-tether_${version}_${info.suffix}`;
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
        bundledScript,
      ],
      stdout: "inherit",
      stderr: "inherit",
    });

    const { code } = await command.output();
    if (code !== 0) Deno.exit(code);
  }
}

await Deno.mkdir(dist, { recursive: true });
await bundle();
await compile();
