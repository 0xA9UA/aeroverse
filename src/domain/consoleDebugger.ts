/** MMA FILE SUMMARY
 * Purpose: Defines scoped console debugger observations without engine protocol details.
 * Responsibilities: Endpoint/target identity, hook captures, evidence limits and cleanup outcomes.
 * Public interface: Debugger input/output schemas and their inferred types.
 * Invariants: Caller identity is not authenticated by a debugger stub; observations are not hardware proof.
 */
import { z } from "zod";
import { localPathStringSchema } from "./localPath.js";

/** Caps bound retained evidence and hostile protocol allocation independently of session duration. */
export const CONSOLE_DEBUGGER_LIMITS = {
  packet_bytes: 65_536,
  memory_bytes_per_capture: 65_536,
  total_memory_bytes: 8 * 1024 * 1024,
  stops: 1024,
  registers: 256,
  hooks: 128,
} as const;
const address = z.string().regex(/^0x[0-9a-fA-F]{1,16}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
export const consoleDebuggerEndpointSchema = z.discriminatedUnion("transport", [
  z.strictObject({
    transport: z.literal("tcp"),
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535),
  }),
  z.strictObject({ transport: z.literal("unix"), path: localPathStringSchema }),
]);
export const consoleDebuggerTargetSchema = z.strictObject({
  platform: z.string().min(1),
  processor: z
    .string()
    .min(1)
    .describe(
      "Guest CPU context selected by this endpoint, for example arm9, arm7 or powerpc.",
    ),
  profile: z.string().min(1),
  game_build_sha256: digest,
  runtime_version: z.string().min(1),
});
const registerSchema = z.strictObject({
  name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*$/),
  number: z.number().int().min(0).max(65535),
  bits: z.union([
    z.literal(8),
    z.literal(16),
    z.literal(32),
    z.literal(64),
    z.literal(128),
  ]),
  byte_order: z.enum(["big", "little"]),
});
const hookSchema = z.strictObject({
  label: z.string().min(1),
  kind: z.enum(["native", "ipc", "network"]),
  address,
  instruction_size: z
    .union([z.literal(2), z.literal(4)])
    .default(4)
    .describe(
      "RSP breakpoint kind in bytes; select 2 explicitly for Thumb instructions.",
    ),
  memory: z
    .array(
      z.strictObject({
        label: z.string().min(1),
        address_register: z.string().min(1),
        offset: z.number().int().min(-0x7fffffff).max(0x7fffffff).default(0),
        length: z
          .number()
          .int()
          .positive()
          .max(CONSOLE_DEBUGGER_LIMITS.memory_bytes_per_capture),
        length_register: z.string().min(1).optional(),
      }),
    )
    .max(16)
    .default([]),
});
/** Live attachment changes run state and breakpoints; no process launch or arbitrary monitor commands. */
export const observeConsoleDebuggerInputSchema = z.strictObject({
  provider: z.enum(["dolphin", "gdb-remote", "openocd"]),
  endpoint: consoleDebuggerEndpointSchema,
  target: consoleDebuggerTargetSchema,
  hooks: z.array(hookSchema).max(CONSOLE_DEBUGGER_LIMITS.hooks).default([]),
  breakpoint_scope: z
    .literal("exclusive-session")
    .optional()
    .describe(
      "Required with hooks: the selected runtime has no other breakpoint owner. RSP cannot enumerate pre-existing Dolphin GUI breakpoints.",
    ),
  register_map: z
    .array(registerSchema)
    .min(1)
    .max(CONSOLE_DEBUGGER_LIMITS.registers)
    .optional()
    .describe(
      "Required for generic/OpenOCD endpoints; must include a register named pc. Dolphin uses its explicit big-endian map.",
    ),
  duration_ms: z.number().int().min(1).max(600_000).default(10_000),
  command_timeout_ms: z.number().int().min(1).max(30_000).default(2_000),
  cleanup_timeout_ms: z.number().int().min(1).max(30_000).default(2_000),
  max_stops: z
    .number()
    .int()
    .positive()
    .max(CONSOLE_DEBUGGER_LIMITS.stops)
    .default(64),
  resume_on_finish: z
    .boolean()
    .describe(
      "Explicit final run-state policy. False requests a halted target; true resumes before disconnect. Neither kills or resets the target.",
    ),
  memory_policy: z.enum(["hash", "bytes"]).default("hash"),
});
const hookIdentity = hookSchema.omit({ memory: true });
const memoryObservation = z
  .strictObject({
    label: z.string(),
    address,
    requested_bytes: z
      .string()
      .max(39)
      .regex(/^[0-9]+$/)
      .describe(
        "Exact unsigned register-selected length in decimal, without JavaScript number rounding.",
      ),
    bytes: z
      .number()
      .int()
      .nonnegative()
      .max(CONSOLE_DEBUGGER_LIMITS.memory_bytes_per_capture),
    sha256: digest,
    content_base64: z
      .string()
      .max(4 * Math.ceil(CONSOLE_DEBUGGER_LIMITS.memory_bytes_per_capture / 3))
      .nullable(),
    truncated: z.boolean(),
  })
  .superRefine((value, context) => {
    if (!/^[0-9]+$/.test(value.requested_bytes)) return;
    const requested = BigInt(value.requested_bytes);
    if (
      BigInt(value.bytes) > requested ||
      value.truncated !== requested > BigInt(value.bytes)
    )
      context.addIssue({
        code: "custom",
        message:
          "Captured byte count and truncation must preserve the exact requested length.",
      });
  });
/** A successful Result can retain partial observations and incomplete cleanup after live attachment. */
export const consoleDebuggerObservationSchema = z.strictObject({
  observation_id: z.string(),
  provider: z.enum(["dolphin", "gdb-remote", "openocd"]),
  endpoint: consoleDebuggerEndpointSchema,
  target: consoleDebuggerTargetSchema,
  target_identity: z.literal("caller-declared-not-authenticated-by-stub"),
  authority: z.enum(["emulator", "hardware-gdbstub", "unverified-gdbstub"]),
  started_at: z.string(),
  ended_at: z.string(),
  completion: z.enum(["completed", "cancelled", "timeout", "partial"]),
  failure: z.string().nullable(),
  negotiated_features: z.array(z.string()),
  stops: z.array(
    z.strictObject({
      stop_sequence: z.number().int().nonnegative(),
      observed_at: z.string(),
      monotonic_ms: z.number().nonnegative(),
      reason: z.enum([
        "initial-interrupt",
        "initial-stop-query",
        "stop-reply",
        "step-over",
      ]),
      signal: z.string().nullable(),
      pc: address.nullable(),
      hook: hookIdentity.nullable(),
      registers: z.array(
        z.strictObject({
          name: z.string(),
          value: z.string().regex(/^0x[0-9a-fA-F]{1,32}$/),
          bits: z.number().int().positive(),
        }),
      ),
      memory: z.array(memoryObservation),
      limitations: z.array(z.string()),
    }),
  ),
  cleanup: z.strictObject({
    status: z.enum(["complete", "incomplete"]),
    remaining_breakpoints: z.array(address),
    run_state: z.enum(["running-requested", "halted-observed", "unknown"]),
    reason: z.string().nullable(),
  }),
  limitations: z.array(z.string()),
});
export type ObserveConsoleDebuggerInput = z.output<
  typeof observeConsoleDebuggerInputSchema
>;
export type ConsoleDebuggerObservation = z.output<
  typeof consoleDebuggerObservationSchema
>;
export type ConsoleDebuggerRegister = z.output<typeof registerSchema>;
export type ConsoleDebuggerStop = ConsoleDebuggerObservation["stops"][number];
