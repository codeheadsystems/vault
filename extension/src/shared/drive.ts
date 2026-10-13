// Runs a vault-client procedure to its end: requests go to the server, prompts and saves to the
// caller's handlers.

import type { Input, Procedure, Prompt, Step } from "vault-wasm";
import { send, type Server } from "./transport.ts";

export type DoneStep = Extract<Step, { type: "done" }>;
export type SaveStep = Extract<Step, { type: "save" }>;

export interface Handlers {
  /** Answers a prompt; `{ type: "answer", declined: true }` declines it. */
  prompt(prompt: Prompt): Promise<Input>;
  /** Shows the kit and runs applySave; the procedure then continues with "saved". */
  save?(step: SaveStep): Promise<void>;
  /** The transport; tests replace it. */
  send?(step: Extract<Step, { type: "request" }>): Promise<Input>;
}

export const DECLINE: Input = { type: "answer", declined: true };

export async function drive(proc: Procedure, server: Server, handlers: Handlers): Promise<DoneStep> {
  let step = proc.start(Date.now());
  for (;;) {
    let input: Input;
    switch (step.type) {
      case "done":
        return step;
      case "request":
        input = await (handlers.send ?? ((s) => send(server, s)))(step);
        break;
      case "prompt":
        input = await handlers.prompt(step.prompt);
        break;
      case "save":
        if (!handlers.save) throw new Error("this procedure cannot save here");
        await handlers.save(step);
        input = { type: "saved" };
        break;
    }
    try {
      step = proc.step(input, Date.now());
    } finally {
      // The module copied any key in the answer; zero the caller's copy.
      if (input.type === "answer") {
        input.secretKey?.fill(0);
        input.vaultId?.fill(0);
      }
    }
  }
}
