// MMA FILE SUMMARY
// Purpose: Defines portable action, code, IPC and packet correlation contracts.
// Responsibilities: Preserve source identity, clock uncertainty and inferred edge semantics.
// Public interface: Correlation input/report schemas and types.
// Invariants: Input events are reported facts; timestamps alone never prove causality.
import { z } from "zod";
import { prefixedDigestSchema } from "./digests.js";
import { consoleNetworkCaptureSchema } from "./consoleNetworkCapture.js";
import { consoleDebuggerObservationSchema } from "./consoleDebugger.js";

const digest = z.string().regex(/^[0-9a-f]{64}$/);
const integer = z
  .string()
  .regex(/^-?(0|[1-9][0-9]*)$/)
  .max(40);
const unsigned = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/)
  .max(40);
const identity = z.string().min(1).max(512);

export const consoleObservationTargetSchema = z.strictObject({
  platform_id: identity,
  profile_version: identity,
  game_build_id: identity.describe(
    "Title/region/revision identity selected for this run.",
  ),
  game_sha256: digest.describe(
    "SHA-256 of the selected game image; runtime binding must be established separately.",
  ),
});

const sourceSchema = z.strictObject({
  artifact_sha256: digest,
  locator: identity.describe(
    "Packet ordinal, JSON pointer, trace record or other exact producer location.",
  ),
  evidence_id: prefixedDigestSchema("ev").optional(),
});
const endpointSchema = z.strictObject({
  address: identity,
  port: z.number().int().min(0).max(65535),
});
const flowSchema = z.strictObject({
  transport: z.enum(["tcp", "udp"]),
  source: endpointSchema,
  destination: endpointSchema,
  connection_id: identity
    .optional()
    .describe(
      "Producer connection generation; a reused socket or 5-tuple is not identity.",
    ),
});

export const consoleObservationEventSchema = z.strictObject({
  event_id: identity,
  session_id: identity,
  game_sha256: digest,
  kind: z.enum(["action", "native", "ipc", "network"]),
  label: z.string().min(1).max(4096),
  clock_id: identity,
  timestamp_ns: integer.max(30).nullable(),
  source: sourceSchema,
  thread_id: identity.optional(),
  cpu: identity.optional(),
  code: z
    .strictObject({
      address: identity,
      module_sha256: digest.nullable(),
      symbol: identity.nullable(),
    })
    .optional(),
  ipc: z
    .strictObject({
      channel: identity,
      operation: identity,
      request_id: identity.nullable(),
    })
    .optional(),
  flow: flowSchema.optional(),
  network_message: z
    .discriminatedUnion("protocol", [
      z.strictObject({
        protocol: z.literal("http"),
        status: z.enum(["complete", "incomplete", "unsupported", "invalid"]),
        kind: z.enum(["request", "response"]),
        method: z.string().max(65536).nullable(),
        target: z.string().max(65536).nullable(),
        status_code: z.number().int().nonnegative().nullable(),
      }),
      z.strictObject({
        protocol: z.literal("dns"),
        status: z.enum(["complete", "incomplete", "unsupported", "invalid"]),
        query: z.boolean(),
        question_names: z.array(z.string().max(1024)).max(16),
      }),
    ])
    .optional(),
  payload: z
    .strictObject({
      sha256: digest,
      bytes: z
        .number()
        .int()
        .nonnegative()
        .max(64 * 1024 * 1024),
      complete: z.boolean(),
      representation: z.enum([
        "application-buffer",
        "transport-segment",
        "datagram",
        "decoded-message",
      ]),
    })
    .optional(),
  parent: z
    .strictObject({
      event_id: identity,
      basis: z.enum(["producer-propagated-id", "analyst-declared"]),
      evidence: z.string().min(1).max(4096),
    })
    .optional(),
  limitations: z.array(z.string().max(4096)).max(64).default([]),
});

/** Limits bound event storage and potentially quadratic candidate/edge expansion. */
export const CONSOLE_CORRELATION_LIMITS = {
  events: 10_000,
  edges: 50_000,
  candidateComparisons: 2_000_000,
} as const;

export const correlateConsoleObservationsInputSchema = z.strictObject({
  target: consoleObservationTargetSchema,
  session_id: identity,
  events: z
    .array(consoleObservationEventSchema)
    .max(CONSOLE_CORRELATION_LIMITS.events)
    .default([]),
  network_captures: z
    .array(
      z.strictObject({
        clock_id: identity,
        report: consoleNetworkCaptureSchema,
        evidence_id: prefixedDigestSchema("ev").optional(),
      }),
    )
    .max(64)
    .default([]),
  debugger_observations: z
    .array(
      z.strictObject({
        clock_id: identity,
        report: consoleDebuggerObservationSchema,
        evidence_id: prefixedDigestSchema("ev").optional(),
      }),
    )
    .max(64)
    .default([]),
  clocks: z
    .array(
      z.strictObject({
        clock_id: identity,
        offset_ns: integer
          .max(30)
          .describe("Add to producer time to obtain the session clock."),
        uncertainty_ns: unsigned,
        evidence: z
          .string()
          .min(1)
          .max(4096)
          .describe(
            "How offset and uncertainty were measured; emulator guest time is not host time.",
          ),
      }),
    )
    .max(128),
  window_ns: unsigned
    .default("250000000")
    .describe("Candidate time window, not a causal assertion."),
  max_edges: z
    .number()
    .int()
    .min(1)
    .max(CONSOLE_CORRELATION_LIMITS.edges)
    .default(10_000),
  client_addresses: z
    .array(identity)
    .max(128)
    .default([])
    .describe(
      "Exact captured client addresses, after any NAT, for endpoint direction.",
    ),
});

export const consoleCorrelationEdgeSchema = z.strictObject({
  from: identity,
  to: identity,
  relationship: z.enum([
    "reported-parent",
    "analyst-hypothesis",
    "same-payload",
    "temporal-candidate",
  ]),
  confidence: z.enum(["derived", "inferred"]),
  causal_proof: z.literal(false),
  explanation: z.string(),
});
const requirementSchema = z.strictObject({
  id: identity,
  description: z.string(),
  status: z.literal("unverified"),
  evidence_events: z.array(identity),
});
export const consoleCorrelationSchema = z.strictObject({
  target: consoleObservationTargetSchema,
  session_id: identity,
  timeline: z.array(
    z.strictObject({
      event: consoleObservationEventSchema,
      aligned_timestamp_ns: integer.nullable(),
      uncertainty_ns: unsigned.nullable(),
    }),
  ),
  edges: z.array(consoleCorrelationEdgeSchema),
  unresolved: z.array(
    z.strictObject({ event_id: identity, reason: z.string() }),
  ),
  coverage: z.strictObject({
    event_count: z.number().int().nonnegative(),
    edges_returned: z.number().int().nonnegative(),
    candidate_comparisons: z.number().int().nonnegative(),
    complete: z
      .boolean()
      .describe(
        "All candidate graph work for the supplied event set completed; runtime and protocol coverage remain separate.",
      ),
    truncation_reason: z.string().nullable(),
  }),
  backend_contract: z.strictObject({
    readiness: z.literal("requirements-only"),
    fully_functional_replacement_verified: z.literal(false),
    services: z.array(
      z.strictObject({
        transport: z.enum(["tcp", "udp"]),
        endpoint: endpointSchema,
        evidence_events: z.array(identity),
        outbound_event_ids: z.array(identity),
        inbound_event_ids: z.array(identity),
        outbound_message_event_ids: z.array(identity),
        inbound_message_event_ids: z.array(identity),
        observed_http_requests: z.array(
          z.strictObject({
            event_id: identity,
            method: z.string().nullable(),
            target: z.string().nullable(),
            status: z.enum([
              "complete",
              "incomplete",
              "unsupported",
              "invalid",
            ]),
          }),
        ),
        protocol_semantics: z.literal("unknown"),
      }),
    ),
    scenarios: z.array(
      z.strictObject({
        action_event_id: identity,
        action: z.string(),
        reported_chain_event_ids: z.array(identity),
        candidate_event_ids: z.array(identity),
        requirements: z.array(requirementSchema),
      }),
    ),
    requirements: z.array(requirementSchema),
  }),
  limitations: z.array(z.string()),
});

export type ConsoleObservationEvent = z.output<
  typeof consoleObservationEventSchema
>;
export type ConsoleCorrelationInput = z.output<
  typeof correlateConsoleObservationsInputSchema
>;
export type ConsoleCorrelationReport = z.output<
  typeof consoleCorrelationSchema
>;
export type ConsoleCorrelationEdge = z.output<
  typeof consoleCorrelationEdgeSchema
>;
