/** MMA FILE SUMMARY
 * Purpose: Validates explicit console debugger authority and selects source-bound register maps.
 * Responsibilities: Endpoint identity, exclusive hook scope and per-CPU register prerequisites.
 * Public interface: ConsoleDebuggerAdapter.observe(); Dolphin and melonDS reference register maps.
 * Collaborators: ConsoleDebuggerSession owns each scoped socket and hook lifecycle.
 * Invariants: No discovery, process launch or implicit console/hardware capability claims.
 */
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import { err, type Result } from "../../domain/result.js";
import {
  observeConsoleDebuggerInputSchema,
  type ObserveConsoleDebuggerInput,
  type ConsoleDebuggerObservation,
  type ConsoleDebuggerRegister,
} from "../../domain/consoleDebugger.js";
import { ConsoleDebuggerSession } from "./ConsoleDebuggerSession.js";
const OPERATION = "observe_console_debugger";
/** Dolphin's g packet omits PC/LR; individual p requests preserve the upstream register numbering. */
export const DOLPHIN_REGISTERS: readonly ConsoleDebuggerRegister[] = [
  ...Array.from({ length: 32 }, (_, number) => ({
    name: `r${number}`,
    number,
    bits: 32 as const,
    byte_order: "big" as const,
  })),
  { name: "pc", number: 64, bits: 32, byte_order: "big" },
  { name: "lr", number: 67, bits: 32, byte_order: "big" },
];
/** melonDS Handle_p uses GdbArch.h's enum directly; CPSR is 16 despite its target XML declaring 25.
 * Source: https://github.com/melonDS-emu/melonDS/blob/master/src/debug/GdbCmds.cpp
 * Select the ARM9 or ARM7 endpoint independently; this map does not authenticate that selection.
 */
export const MELONDS_ARM_REGISTERS: readonly ConsoleDebuggerRegister[] = [
  ...Array.from({ length: 13 }, (_, number) => ({
    name: `r${number}`,
    number,
    bits: 32 as const,
    byte_order: "little" as const,
  })),
  { name: "sp", number: 13, bits: 32, byte_order: "little" },
  { name: "lr", number: 14, bits: 32, byte_order: "little" },
  { name: "pc", number: 15, bits: 32, byte_order: "little" },
  { name: "cpsr", number: 16, bits: 32, byte_order: "little" },
];
function invalid(reason: string): Result<never, AnalysisError> {
  return err(
    new AnalysisInputError(OPERATION, undefined, [
      { path: [], reason: "invalid_value", message: reason },
    ]),
  );
}
function hookProblem(
  input: ObserveConsoleDebuggerInput,
  registers: readonly ConsoleDebuggerRegister[],
): string | null {
  const names = new Set(registers.map((register) => register.name));
  if (
    names.size !== registers.length ||
    new Set(registers.map((register) => register.number)).size !==
      registers.length
  )
    return "Register names and numbers must be unique.";
  if (
    new Set(input.hooks.map((hook) => BigInt(hook.address).toString())).size !==
      input.hooks.length ||
    new Set(input.hooks.map((hook) => hook.label)).size !== input.hooks.length
  )
    return "Hook labels and addresses must be unique.";
  for (const hook of input.hooks) {
    if (BigInt(hook.address) > 0xffffffffn && input.provider === "dolphin")
      return "Dolphin hook addresses must fit guest 32-bit memory.";
    if (input.provider === "dolphin" && hook.instruction_size !== 4)
      return "Dolphin PPC hooks require four-byte instructions.";
    for (const capture of hook.memory)
      if (
        !names.has(capture.address_register) ||
        (capture.length_register !== undefined &&
          !names.has(capture.length_register))
      )
        return "Memory capture registers must occur in the selected register map.";
  }
  return null;
}
/** Attachment and cleanup belong to one call; endpoint possession does not grant process-control authority. */
export class ConsoleDebuggerAdapter {
  async observe(
    rawInput: ObserveConsoleDebuggerInput,
    options?: ExecutionOptions,
  ): Promise<Result<ConsoleDebuggerObservation, AnalysisError>> {
    const parsed = observeConsoleDebuggerInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return invalid(
        "Debugger input does not satisfy its endpoint, identity or evidence-budget contract.",
      );
    const input = parsed.data;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    if (input.endpoint.transport === "unix" && !isAbsolute(input.endpoint.path))
      return invalid("Unix debugger socket path must be absolute.");
    if (
      input.endpoint.transport === "tcp" &&
      /[\s\0]/u.test(input.endpoint.host)
    )
      return invalid("TCP debugger host must not contain whitespace or NUL.");
    if (
      input.hooks.length > 0 &&
      input.breakpoint_scope !== "exclusive-session"
    )
      return invalid(
        "Hooks require an exclusive breakpoint session; RSP cannot distinguish pre-existing same-address GUI breakpoints.",
      );
    if (input.provider === "dolphin" && input.register_map !== undefined)
      return invalid(
        "Dolphin uses its source-bound register map; select gdb-remote for a caller-supplied map.",
      );
    const registers =
      input.provider === "dolphin" ? DOLPHIN_REGISTERS : input.register_map;
    if (!registers || !registers.some((register) => register.name === "pc"))
      return invalid(
        "Generic/OpenOCD stubs require an explicit register map including pc.",
      );
    const problem = hookProblem(input, registers);
    if (problem !== null) return invalid(problem);
    return new ConsoleDebuggerSession(input, registers, options).run();
  }
}
