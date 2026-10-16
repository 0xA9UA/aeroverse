// MMA FILE SUMMARY
// Purpose: Correlates console action/code/IPC/network events with explicit clock and identity boundaries.
// Responsibilities: Validate joins, retain unresolved events, bound candidate expansion and derive requirements.
// Public interface: correlateConsoleObservations().
// Collaborators: consoleObservation contracts; consoleBackendContract for reconstruction obligations.
// Invariants: No execution or packet replay; temporal and byte matches never become causal proof.
import { AnalysisInputError } from "./analysisErrorCore.js";
import type { AnalysisError } from "./analysisErrorBase.js";
import { analysisInputErrorFromIssues } from "./inputIssueProjection.js";
import { err, ok, type Result } from "./result.js";
import {
  CONSOLE_CORRELATION_LIMITS,
  correlateConsoleObservationsInputSchema,
  type ConsoleCorrelationInput,
  type ConsoleCorrelationEdge,
  type ConsoleCorrelationReport,
  type ConsoleObservationEvent,
} from "./consoleObservation.js";
import { deriveConsoleBackendContract } from "./consoleBackendContract.js";
import { normalizeConsoleObservationReports } from "./consoleObservationImport.js";

const OPERATION = "correlate_console_observations";
const invalid = (message: string): Result<never, AnalysisError> =>
  err(
    new AnalysisInputError(OPERATION, undefined, [
      { path: [], reason: "invalid_value", message },
    ]),
  );
const rank = { action: 0, native: 1, ipc: 2, network: 3 } as const;

const validateEventIdentities = (
  input: ConsoleCorrelationInput,
): Result<Map<string, ConsoleObservationEvent>, AnalysisError> => {
  const byId = new Map<string, ConsoleObservationEvent>();
  for (const event of input.events) {
    if (byId.has(event.event_id))
      return invalid(`Duplicate event identity: ${event.event_id}`);
    if (
      event.session_id !== input.session_id ||
      event.game_sha256 !== input.target.game_sha256
    )
      return invalid(
        "All events must belong to the selected session and game digest; cross-run joins require a separate comparison.",
      );
    byId.set(event.event_id, event);
  }
  if (
    new Set(input.clocks.map((clock) => clock.clock_id)).size !==
    input.clocks.length
  )
    return invalid("Clock IDs must be unique.");
  // Reject cycles without recursive traversal or quadratic ancestor walks.
  const completeParents = new Set<string>();
  for (const event of input.events) {
    const path = new Set<string>();
    let current: ConsoleObservationEvent | undefined = event;
    while (current !== undefined && !completeParents.has(current.event_id)) {
      if (path.has(current.event_id))
        return invalid("Parent relationships must be acyclic.");
      path.add(current.event_id);
      current =
        current.parent === undefined
          ? undefined
          : byId.get(current.parent.event_id);
    }
    for (const id of path) completeParents.add(id);
  }
  return ok(byId);
};

const alignTimeline = (
  input: ConsoleCorrelationInput,
  unresolved: ConsoleCorrelationReport["unresolved"],
): ConsoleCorrelationReport["timeline"] => {
  const clocks = new Map(input.clocks.map((clock) => [clock.clock_id, clock]));
  const timeline: ConsoleCorrelationReport["timeline"] = input.events.map(
    (event) => {
      const clock = clocks.get(event.clock_id);
      if (clock === undefined || event.timestamp_ns === null) {
        unresolved.push({
          event_id: event.event_id,
          reason:
            "No measured clock mapping or producer timestamp; temporal correlation is unavailable.",
        });
        return { event, aligned_timestamp_ns: null, uncertainty_ns: null };
      }
      return {
        event,
        aligned_timestamp_ns: (
          BigInt(event.timestamp_ns) + BigInt(clock.offset_ns)
        ).toString(),
        uncertainty_ns: clock.uncertainty_ns,
      };
    },
  );
  timeline.sort((a, b) => {
    if (a.aligned_timestamp_ns === null)
      return b.aligned_timestamp_ns === null ? 0 : 1;
    if (b.aligned_timestamp_ns === null) return -1;
    const left = BigInt(a.aligned_timestamp_ns),
      right = BigInt(b.aligned_timestamp_ns);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return timeline;
};

class EdgeCollector {
  readonly edges: ConsoleCorrelationEdge[] = [];
  readonly keys = new Set<string>();
  comparisons = 0;
  truncation: string | null = null;
  constructor(readonly maximum: number) {}
  add(
    from: string,
    to: string,
    relationship: ConsoleCorrelationEdge["relationship"],
    explanation: string,
  ): void {
    const key = JSON.stringify([from, to, relationship]);
    if (this.keys.has(key)) return;
    if (this.edges.length >= this.maximum) {
      this.truncation =
        "Selected edge capacity reached; remaining candidate links are unknown.";
      return;
    }
    this.keys.add(key);
    this.edges.push({
      from,
      to,
      relationship,
      confidence:
        relationship === "reported-parent" || relationship === "same-payload"
          ? "derived"
          : "inferred",
      causal_proof: false,
      explanation,
    });
  }
  compare(): boolean {
    if (this.comparisons >= CONSOLE_CORRELATION_LIMITS.candidateComparisons) {
      this.truncation =
        "Candidate comparison capacity reached; remaining links are unknown.";
      return false;
    }
    this.comparisons += 1;
    return this.truncation === null;
  }
}

const joinReportedParents = (
  input: ConsoleCorrelationInput,
  byId: ReadonlyMap<string, ConsoleObservationEvent>,
  collector: EdgeCollector,
  unresolved: ConsoleCorrelationReport["unresolved"],
): void => {
  for (const event of input.events) {
    if (event.parent === undefined) continue;
    if (!byId.has(event.parent.event_id)) {
      unresolved.push({
        event_id: event.event_id,
        reason: `Parent ${event.parent.event_id} is absent from the supplied trace.`,
      });
      continue;
    }
    collector.add(
      event.parent.event_id,
      event.event_id,
      event.parent.basis === "producer-propagated-id"
        ? "reported-parent"
        : "analyst-hypothesis",
      event.parent.evidence,
    );
  }
};

const joinPayloads = (
  input: ConsoleCorrelationInput,
  collector: EdgeCollector,
): void => {
  const payloads = new Map<string, ConsoleObservationEvent[]>();
  for (const event of input.events) {
    const payload = event.payload;
    if (payload === undefined || !payload.complete || payload.bytes === 0)
      continue;
    const key = `${payload.sha256}:${payload.bytes}`;
    const bucket = payloads.get(key) ?? [];
    bucket.push(event);
    payloads.set(key, bucket);
  }
  for (const bucket of payloads.values()) {
    for (
      let i = 0;
      i < bucket.length && collector.truncation === null;
      i += 1
    ) {
      const a = bucket[i];
      if (a === undefined) continue;
      for (const b of bucket.slice(i + 1)) {
        if (!collector.compare()) break;
        if (a.kind === b.kind || (a.kind !== "network" && b.kind !== "network"))
          continue;
        const [from, to] = rank[a.kind] < rank[b.kind] ? [a, b] : [b, a];
        collector.add(
          from.event_id,
          to.event_id,
          "same-payload",
          "Producer reports equal nonempty complete byte hashes and lengths across layers; repeated bytes and independent calls remain possible.",
        );
      }
    }
  }
};

const joinTimeCandidates = (
  timeline: ConsoleCorrelationReport["timeline"],
  windowNs: string,
  collector: EdgeCollector,
): void => {
  const window = BigInt(windowNs);
  for (
    let i = 0;
    i < timeline.length && collector.truncation === null;
    i += 1
  ) {
    const a = timeline[i];
    if (a === undefined || a.aligned_timestamp_ns === null) continue;
    for (let j = i + 1; j < timeline.length; j += 1) {
      const b = timeline[j];
      if (b === undefined || b.aligned_timestamp_ns === null) break;
      if (!collector.compare()) break;
      if (a.event.kind === b.event.kind) continue;
      const [from, to] =
        rank[a.event.kind] < rank[b.event.kind] ? [a, b] : [b, a];
      const distance =
        BigInt(to.aligned_timestamp_ns!) - BigInt(from.aligned_timestamp_ns!);
      const uncertainty =
        BigInt(from.uncertainty_ns ?? "0") + BigInt(to.uncertainty_ns ?? "0");
      if (distance + uncertainty < 0n || distance - uncertainty > window)
        continue;
      collector.add(
        from.event.event_id,
        to.event.event_id,
        "temporal-candidate",
        "Clock intervals overlap a possible forward interval within the selected window; scheduling, polling and unrelated traffic can produce the same timing.",
      );
    }
  }
};

const flagTimeContradictions = (
  timeline: ConsoleCorrelationReport["timeline"],
  unresolved: ConsoleCorrelationReport["unresolved"],
): void => {
  const aligned = new Map(
    timeline.map((entry) => [entry.event.event_id, entry]),
  );
  // Explicit parent timing inversions are retained as contradictions, never repaired.
  for (const { event } of timeline) {
    const child = aligned.get(event.event_id);
    const parent =
      event.parent === undefined
        ? undefined
        : aligned.get(event.parent.event_id);
    if (
      child?.aligned_timestamp_ns != null &&
      parent?.aligned_timestamp_ns != null &&
      BigInt(child.aligned_timestamp_ns) + BigInt(child.uncertainty_ns ?? "0") <
        BigInt(parent.aligned_timestamp_ns) -
          BigInt(parent.uncertainty_ns ?? "0")
    )
      unresolved.push({
        event_id: event.event_id,
        reason:
          "Reported parent occurs after child outside clock uncertainty; investigate timestamp or propagation semantics.",
      });
  }
};

export const correlateConsoleObservations = (
  raw: unknown,
): Result<ConsoleCorrelationReport, AnalysisError> => {
  const parsed = correlateConsoleObservationsInputSchema.safeParse(raw);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, parsed.error.issues, raw),
    );
  const normalized = normalizeConsoleObservationReports(parsed.data);
  if (!normalized.ok) return normalized;
  const input = { ...parsed.data, events: normalized.value };
  const identities = validateEventIdentities(input);
  if (!identities.ok) return identities;
  const unresolved: ConsoleCorrelationReport["unresolved"] = [];
  const timeline = alignTimeline(input, unresolved);
  const collector = new EdgeCollector(input.max_edges);
  joinReportedParents(input, identities.value, collector, unresolved);
  joinPayloads(input, collector);
  joinTimeCandidates(timeline, input.window_ns, collector);
  flagTimeContradictions(timeline, unresolved);
  const backend = deriveConsoleBackendContract(input, collector.edges);
  if (!backend.complete)
    collector.truncation ??=
      "Scenario graph expansion reached the selected edge capacity; scenario coverage is partial.";
  return ok({
    target: input.target,
    session_id: input.session_id,
    timeline,
    edges: collector.edges,
    unresolved,
    coverage: {
      event_count: timeline.length,
      edges_returned: collector.edges.length,
      candidate_comparisons: collector.comparisons,
      complete: collector.truncation === null,
      truncation_reason: collector.truncation,
    },
    backend_contract: backend.contract,
    limitations: [
      "Input events and propagated identifiers are producer/analyst reports; this operation does not observe or authenticate a live runtime.",
      "Clock alignment requires an independently measured offset and uncertainty; guest cycles and host capture timestamps are not interchangeable.",
      "Timing, equal payloads and caller-declared parent relationships do not independently prove causality.",
      "Encrypted payloads, TCP reassembly, application framing and original server responses require additional evidence.",
      "Service direction uses only explicitly supplied client addresses; missing or ambiguous direction leaves endpoints unresolved.",
    ],
  });
};
