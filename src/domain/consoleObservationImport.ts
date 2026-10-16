// MMA FILE SUMMARY
// Purpose: Normalizes retained packet/debugger reports into source-bound correlation events.
// Public interface: normalizeConsoleObservationReports().
// Collaborators: consoleObservation contracts; canonicalDigest identifies retained debugger report JSON.
// Invariants: Runtime/game association is caller-declared; hooks never invent IPC semantics or causal parents.
import { createHash } from "node:crypto";
import type { AnalysisError } from "./analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "./analysisErrorCore.js";
import { digestCanonicalValue } from "./canonicalDigest.js";
import type {
  ConsoleDebuggerObservation,
  ConsoleDebuggerStop,
} from "./consoleDebugger.js";
import type {
  ConsoleNetworkCapture,
  ConsoleNetworkPacket,
} from "./consoleNetworkCapture.js";
import {
  CONSOLE_CORRELATION_LIMITS,
  consoleObservationEventSchema,
  type ConsoleCorrelationInput,
  type ConsoleObservationEvent,
} from "./consoleObservation.js";
import { err, ok, type Result } from "./result.js";
import { networkMessageEvent } from "./consoleNetworkMessageEvents.js";

const OPERATION = "correlate_console_observations";
const invalid = (
  message: string,
  path: (string | number)[],
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path, reason: "invalid_value", message },
  ]);
const declaredBinding =
  "Session and game association are caller-declared; this retained report does not authenticate the runtime/game binding.";

/** Returns existing events followed by imports; rejects total expansion before allocating events. */
export const normalizeConsoleObservationReports = (
  input: ConsoleCorrelationInput,
): Result<ConsoleObservationEvent[], AnalysisError> => {
  let eventCount = input.events.length;
  for (const capture of input.network_captures)
    eventCount +=
      capture.report.packets.length + capture.report.messages.length;
  for (const observation of input.debugger_observations) {
    eventCount += observation.report.stops.length;
    for (const stop of observation.report.stops)
      eventCount += stop.memory.length;
  }
  if (eventCount > CONSOLE_CORRELATION_LIMITS.events)
    return err(
      new AnalysisResourceConstraintError(
        OPERATION,
        "memory",
        "Supplied events and report imports exceed the canonical event capacity; select packet ordinals or smaller debugger observations.",
        {
          maximum_events: CONSOLE_CORRELATION_LIMITS.events,
          requested_events: eventCount,
        },
      ),
    );
  const events: ConsoleObservationEvent[] = [...input.events];
  for (const capture of input.network_captures) {
    for (const packet of capture.report.packets)
      events.push(
        withEvidenceAnnotation(
          packetEvent(input, capture.clock_id, capture.report, packet),
          capture.evidence_id,
        ),
      );
    const reportDigest = digestCanonicalValue(
      capture.report,
      "Console network capture report",
    );
    const packets = new Map(
      capture.report.packets.map((packet) => [packet.id, packet]),
    );
    for (const [index, message] of capture.report.messages.entries())
      events.push(
        withEvidenceAnnotation(
          networkMessageEvent(
            {
              input,
              clockId: capture.clock_id,
              report: capture.report,
              reportDigest,
              packets,
            },
            message,
            index,
          ),
          capture.evidence_id,
        ),
      );
  }
  const debugEvents = importDebuggerEvents(input);
  if (!debugEvents.ok) return debugEvents;
  events.push(...debugEvents.value);
  for (const [index, event] of events.entries()) {
    const checked = consoleObservationEventSchema.safeParse(event);
    if (!checked.success)
      return err(
        invalid(
          "Imported event exceeds canonical field/limitation bounds or contains inconsistent report data; retain and inspect the original report.",
          ["events", index],
        ),
      );
  }
  return ok(events);
};

/** References remain caller annotations; the application verifies retained payloads before linking. */
const withEvidenceAnnotation = (
  event: ConsoleObservationEvent,
  evidenceId: string | undefined,
): ConsoleObservationEvent =>
  evidenceId === undefined
    ? event
    : {
        ...event,
        source: { ...event.source, evidence_id: evidenceId },
      };

const packetEvent = (
  input: ConsoleCorrelationInput,
  clockId: string,
  report: ConsoleNetworkCapture,
  packet: ConsoleNetworkPacket,
): ConsoleObservationEvent => ({
  event_id: packet.id,
  session_id: input.session_id,
  game_sha256: input.target.game_sha256,
  kind: "network",
  label: `${packet.flow?.transport.toUpperCase() ?? "Undecoded"} capture packet ${packet.ordinal}`,
  clock_id: clockId,
  timestamp_ns: packet.timestamp_ns,
  source: {
    artifact_sha256: report.artifact.sha256,
    locator: `packet:${packet.ordinal}@file-offset:${packet.offset}`,
  },
  ...(packet.flow === null ? {} : { flow: packet.flow }),
  ...(packet.payload_state !== "available" ||
  packet.payload_sha256 === null ||
  packet.payload_bytes === null
    ? {}
    : {
        payload: {
          sha256: packet.payload_sha256,
          bytes: packet.payload_bytes,
          complete: true,
          representation:
            packet.flow?.transport === "udp"
              ? ("datagram" as const)
              : ("transport-segment" as const),
        },
      }),
  limitations: [
    ...report.limitations,
    ...packet.limitations,
    declaredBinding,
    ...(packet.payload_state === "partial"
      ? ["Partial packet payload is excluded from complete-payload matching."]
      : []),
  ],
});

const stopEvent = (
  context: {
    input: ConsoleCorrelationInput;
    clockId: string;
    report: ConsoleDebuggerObservation;
    reportDigest: string;
  },
  stop: ConsoleDebuggerStop,
  index: number,
): ConsoleObservationEvent => {
  const { input, clockId, report, reportDigest } = context;
  const timestamp = hostTimestamp(stop.observed_at);
  return {
    event_id: `sha256:${reportDigest}/stop:${stop.stop_sequence}`,
    session_id: input.session_id,
    game_sha256: input.target.game_sha256,
    kind: stop.hook?.kind === "ipc" ? "ipc" : "native",
    label:
      stop.hook === null
        ? `Debugger ${stop.reason} stop ${stop.stop_sequence}`
        : `Debugger ${stop.hook.kind} hook ${JSON.stringify(stop.hook.label)} at stop ${stop.stop_sequence}`,
    clock_id: clockId,
    timestamp_ns: timestamp,
    cpu: report.target.processor,
    source: { artifact_sha256: reportDigest, locator: `/stops/${index}` },
    ...(stop.pc === null
      ? {}
      : { code: { address: stop.pc, module_sha256: null, symbol: null } }),
    limitations: [
      ...report.limitations,
      ...stop.limitations,
      declaredBinding,
      "Source digest identifies canonical retained debugger report JSON; it is not a digest of guest code or memory.",
      "Stop time is a debugger-host observation with millisecond resolution; guest-cycle timing and runtime clock alignment are not established.",
      "Hook kind/label are caller declarations; an IPC/network label alone establishes no request, channel or transport flow.",
      ...(stop.hook?.kind === "ipc"
        ? [
            "IPC classification is caller-supplied; request/channel semantics were not decoded.",
          ]
        : []),
      ...(timestamp === null
        ? [
            "The producer's observed_at is not an exact supported millisecond UTC timestamp; temporal correlation is unavailable.",
          ]
        : []),
      ...(report.completion === "completed"
        ? []
        : [
            `Debugger observation completion is ${report.completion}; stop coverage is partial${report.failure === null ? "." : `: ${report.failure}`}`,
          ]),
      ...(report.cleanup.status === "complete"
        ? []
        : [
            `Debugger cleanup is incomplete; final run state/breakpoint ownership needs review${report.cleanup.reason === null ? "." : `: ${report.cleanup.reason}`}`,
          ]),
    ],
  };
};

const hostTimestamp = (value: string): string | null => {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(value))
    return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  const padded = value.replace(
    /(?:\.(\d{1,3}))?Z$/u,
    (_, fraction: string | undefined) => `.${(fraction ?? "").padEnd(3, "0")}Z`,
  );
  return new Date(milliseconds).toISOString() === padded
    ? (BigInt(milliseconds) * 1_000_000n).toString()
    : null;
};

const importDebuggerEvents = (
  input: ConsoleCorrelationInput,
): Result<ConsoleObservationEvent[], AnalysisError> => {
  const events: ConsoleObservationEvent[] = [];
  for (const [
    reportIndex,
    observation,
  ] of input.debugger_observations.entries()) {
    const report = observation.report;
    if (
      report.target.game_build_sha256 !== input.target.game_sha256 ||
      report.target.platform !== input.target.platform_id ||
      report.target.profile !== input.target.profile_version
    )
      return err(
        invalid(
          "Debugger game digest, platform and opaque profile version must exactly match the selected correlation target.",
          ["debugger_observations", reportIndex, "report", "target"],
        ),
      );
    const reportDigest = digestCanonicalValue(
      report,
      "Console debugger report",
    );
    const stopSequences = new Set<number>();
    for (const [index, stop] of report.stops.entries()) {
      if (stopSequences.has(stop.stop_sequence))
        return err(
          invalid("Debugger stop_sequence must be unique within its report.", [
            "debugger_observations",
            reportIndex,
            "report",
            "stops",
            index,
            "stop_sequence",
          ]),
        );
      stopSequences.add(stop.stop_sequence);
      const event = withEvidenceAnnotation(
        stopEvent(
          { input, clockId: observation.clock_id, report, reportDigest },
          stop,
          index,
        ),
        observation.evidence_id,
      );
      events.push(event);
      const buffers = memoryEvents(event, stop, index, reportIndex);
      if (!buffers.ok) return buffers;
      events.push(...buffers.value);
    }
  }
  return ok(events);
};

const memoryEvents = (
  event: ConsoleObservationEvent,
  stop: ConsoleDebuggerStop,
  index: number,
  reportIndex: number,
): Result<ConsoleObservationEvent[], AnalysisError> => {
  const events: ConsoleObservationEvent[] = [];
  for (const [memoryIndex, memory] of stop.memory.entries()) {
    if (memory.content_base64 !== null) {
      const bytes = Buffer.from(memory.content_base64, "base64");
      if (
        bytes.toString("base64") !== memory.content_base64 ||
        bytes.length !== memory.bytes ||
        createHash("sha256").update(bytes).digest("hex") !== memory.sha256
      )
        return err(
          invalid(
            "Debugger buffer bytes disagree with their size, canonical base64 or digest.",
            [
              "debugger_observations",
              reportIndex,
              "report",
              "stops",
              index,
              "memory",
              memoryIndex,
            ],
          ),
        );
    }
    events.push({
      ...event,
      event_id: `${event.event_id}/memory:${memoryIndex}`,
      kind: "native",
      label: `Debugger buffer ${JSON.stringify(memory.label)} at ${memory.address} from stop ${stop.stop_sequence}`,
      source: {
        ...event.source,
        artifact_sha256: event.source.artifact_sha256,
        locator: `/stops/${index}/memory/${memoryIndex}`,
      },
      payload: {
        sha256: memory.sha256,
        bytes: memory.bytes,
        complete:
          !memory.truncated &&
          BigInt(memory.requested_bytes) === BigInt(memory.bytes),
        representation: "application-buffer",
      },
      limitations: [
        ...event.limitations,
        "A memory buffer is an observed range; its relationship to application messages, IPC requests or network sends is not established.",
        ...(memory.truncated ||
        BigInt(memory.requested_bytes) !== BigInt(memory.bytes)
          ? [
              "Captured memory does not cover the requested range; its hash cannot identify a complete requested buffer.",
            ]
          : []),
        ...(memory.content_base64 === null
          ? [
              "Memory bytes were omitted by the debugger report; the supplied digest is a producer-reported measurement.",
            ]
          : []),
      ],
    });
  }
  return ok(events);
};
