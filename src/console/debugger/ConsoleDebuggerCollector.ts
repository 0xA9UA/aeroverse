/** MMA FILE SUMMARY
 * Purpose: Retains partial console register and bounded memory observations at stopped guest contexts.
 * Responsibilities: Register byte order, hook association, exact capture lengths and retained-byte hashes.
 * Collaborators: ConsoleDebuggerSession owns protocol sequencing and run state.
 * Invariants: Read failures preserve earlier facts; labels do not establish API semantics or causation.
 */
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  CONSOLE_DEBUGGER_LIMITS,
  type ConsoleDebuggerObservation,
  type ConsoleDebuggerRegister,
  type ConsoleDebuggerStop,
  type ObserveConsoleDebuggerInput,
} from "../../domain/consoleDebugger.js";
import { RspFailure } from "./RspConnection.js";

export const debuggerErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : "Debugger operation failed.";
export function expectDebuggerReply(reply: string, context: string): string {
  if (reply === "")
    throw new RspFailure("protocol", `Stub does not support ${context}.`);
  if (/^E[0-9a-fA-F]+$/.test(reply))
    throw new RspFailure("protocol", `Stub refused ${context}: ${reply}.`);
  return reply;
}
export const isDebuggerStop = (reply: string): boolean =>
  /^[ST][0-9a-fA-F]{2}/.test(reply);
export function debuggerStopSignal(reply: string): string {
  if (!isDebuggerStop(reply))
    throw new RspFailure(
      "protocol",
      `Expected an all-stop reply; received ${reply.slice(0, 64)}.`,
    );
  return reply.slice(1, 3).toLowerCase();
}
function registerValue(
  reply: string,
  register: ConsoleDebuggerRegister,
): string {
  expectDebuggerReply(reply, `register ${register.name}`);
  if (!/^[0-9a-fA-F]+$/.test(reply) || reply.length !== register.bits / 4)
    throw new RspFailure(
      "protocol",
      `Unexpected width/encoding for register ${register.name}.`,
    );
  const bytes = Buffer.from(reply, "hex");
  if (register.byte_order === "little") bytes.reverse();
  return `0x${BigInt(`0x${bytes.toString("hex")}`).toString(16)}`;
}
type Capture = ObserveConsoleDebuggerInput["hooks"][number]["memory"][number];
/** Holds retained evidence budgets, without controlling breakpoints, target execution or process lifetime. */
export class ConsoleDebuggerCollector {
  #transferred = 0;
  memoryChunkBytes = 256;
  constructor(
    readonly context: {
      input: ObserveConsoleDebuggerInput;
      registers: readonly ConsoleDebuggerRegister[];
      report: ConsoleDebuggerObservation;
      started: number;
    },
    readonly request: (command: string) => Promise<string>,
  ) {}
  async collect(
    signal: string,
    reason: ConsoleDebuggerStop["reason"],
  ): Promise<void> {
    const { report, input, registers, started } = this.context;
    const stop: ConsoleDebuggerStop = {
      stop_sequence: report.stops.length,
      observed_at: new Date().toISOString(),
      monotonic_ms: performance.now() - started,
      reason,
      signal,
      pc: null,
      hook: null,
      registers: [],
      memory: [],
      limitations: [],
    };
    report.stops.push(stop);
    for (const register of registers) {
      const value = registerValue(
        await this.request(`p${register.number.toString(16)}`),
        register,
      );
      stop.registers.push({ name: register.name, value, bits: register.bits });
      if (register.name === "pc") {
        if (BigInt(value) > 0xffffffffffffffffn)
          throw new RspFailure(
            "protocol",
            "PC exceeds supported address coordinates.",
          );
        stop.pc = value;
      }
    }
    const hook = input.hooks.find(
      (candidate) =>
        stop.pc !== null && BigInt(candidate.address) === BigInt(stop.pc),
    );
    if (!hook) return;
    stop.hook = {
      label: hook.label,
      kind: hook.kind,
      address: hook.address,
      instruction_size: hook.instruction_size,
    };
    for (const capture of hook.memory) await this.#captureMemory(stop, capture);
  }
  async #captureMemory(
    stop: ConsoleDebuggerStop,
    capture: Capture,
  ): Promise<void> {
    const { input } = this.context;
    const pointer = stop.registers.find(
      (register) => register.name === capture.address_register,
    )!;
    const address = BigInt(pointer.value) + BigInt(capture.offset);
    const addressEnd =
      input.provider === "dolphin" ? 0x100000000n : 0x10000000000000000n;
    if (address < 0n || address >= addressEnd)
      throw new RspFailure(
        "protocol",
        "Memory capture address exceeds guest coordinates.",
      );
    const sizeRegister = stop.registers.find(
      (register) => register.name === capture.length_register,
    );
    const requested =
      sizeRegister === undefined
        ? BigInt(capture.length)
        : BigInt(sizeRegister.value);
    const size = Number(
      requested < BigInt(capture.length) ? requested : BigInt(capture.length),
    );
    if (address + BigInt(size) > addressEnd)
      throw new RspFailure(
        "protocol",
        "Memory capture range wraps guest coordinates.",
      );
    if (this.#transferred + size > CONSOLE_DEBUGGER_LIMITS.total_memory_bytes)
      throw new RspFailure(
        "protocol",
        "Session memory evidence exceeded its retained-byte budget.",
      );
    const chunks: Buffer[] = [];
    try {
      for (let offset = 0; offset < size; offset += this.memoryChunkBytes) {
        const length = Math.min(this.memoryChunkBytes, size - offset);
        const memory = expectDebuggerReply(
          await this.request(
            `m${(address + BigInt(offset)).toString(16)},${length.toString(16)}`,
          ),
          "memory read",
        );
        if (!/^[0-9a-fA-F]+$/.test(memory) || memory.length !== length * 2)
          throw new RspFailure(
            "protocol",
            "Memory reply does not match the requested bounded range.",
          );
        chunks.push(Buffer.from(memory, "hex"));
      }
    } catch (error) {
      stop.limitations.push(
        `Memory capture ${capture.label} is incomplete: ${debuggerErrorMessage(error)}`,
      );
      throw error;
    } finally {
      const bytes = Buffer.concat(chunks);
      this.#transferred += bytes.length;
      if (bytes.length > 0 || requested === 0n)
        stop.memory.push({
          label: capture.label,
          address: `0x${address.toString(16)}`,
          requested_bytes: requested.toString(),
          bytes: bytes.length,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          content_base64:
            input.memory_policy === "bytes" ? bytes.toString("base64") : null,
          truncated: requested > BigInt(bytes.length),
        });
    }
  }
}
