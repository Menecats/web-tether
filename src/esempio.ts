import { delay } from "@std/async";

async function delayPrint(content: string, wait: number, newLine = true) {
  const encoder = new TextEncoder();
  for (const char of content) {
    await Deno.stdout.write(encoder.encode(char));
    await delay(wait);
  }
  if (newLine) await Deno.stdout.write(encoder.encode("\n"));
}

const memoria: Record<string, string | number> = {};

const velocitaBase = 50;
type Azione =
  | { pausa: () => number }
  | {
    dire: () => string;
    velocita?: () => number;
    chiedi?: () => { cosa: string; come: "string" | "number" };
  };

const azioni: Azione[] = [
  { dire: () => `SONO UN MOSTRO...` },
  { pausa: () => 500 },
  { dire: () => `SONO CATTIVO CATTIVO...` },
  { dire: () => `MI CHIAMO BRUBRI...` },
  {
    dire: () => `TU COME TI CHIAMI?`,
    chiedi: () => ({ cosa: "nome", come: "string" }),
  },
  {
    dire: () => `QUANTI HANNI HAI?`,
    chiedi: () => ({ cosa: "anni", come: "number" }),
  },
  {
    dire: () =>
      `CIAO ${memoria["nome"]}, io ho ${(memoria["anni"] as number) + 1} anni`,
  },
];

console.log("\n");
for (const azione of azioni) {
  if ("pausa" in azione) {
    await delay(azione.pausa());
  }

  if ("dire" in azione) {
    const velocita = azione.velocita?.() ?? velocitaBase;
    const dire = azione.dire();
    await delayPrint(dire, velocita, !azione.chiedi);

    if (azione.chiedi) {
      const domanda = azione.chiedi();

      const risposta = prompt(dire) || "";
      memoria[domanda.cosa] = domanda.come === "string"
        ? risposta
        : parseInt(risposta) || 0;
    }
  }
}
