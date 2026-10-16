// MMA FILE SUMMARY
// Purpose: Preserves console correlation input commitments and verifies retained source references.
// Public interface: consoleCorrelationEvidenceContext().
// Collaborators: Console schemas, canonical hashing and a narrow Evidence reader.
// Invariants: A retained ID alone authenticates no supplied report; unmatched references remain annotations.
import { digestCanonicalValue } from "../domain/canonicalDigest.js";
import type {
  ConsoleCorrelationInput,
  ConsoleCorrelationReport,
} from "../domain/consoleObservation.js";
import type { Evidence } from "../domain/evidence.js";
import { jsonObjectSchema } from "../domain/jsonValue.js";

type Reader = ((id: string) => Evidence | undefined) | undefined;

/** A compact, canonical commitment preserves input choices without duplicating imported reports. */
export const consoleCorrelationEvidenceContext = (
  input: ConsoleCorrelationInput,
  report: ConsoleCorrelationReport,
  evidenceById: Reader,
) => {
  const references = sourceReferences(input, report, evidenceById);
  return {
    parameters: summarizeInput(input),
    evidenceLinks: references.retained,
    limitations: [
      ...report.limitations,
      "Event facts, game identity and source digests are caller supplied; correlation does not inspect or authenticate their source artifacts.",
      ...(references.unverified
        ? [
            "Source Evidence annotations absent from this session or inconsistent with their reported source remain unlinked; retained matching sources alone are linked by this Evidence.",
          ]
        : []),
      ...input.debugger_observations.flatMap(({ report: observation }) => [
        ...(observation.completion === "completed"
          ? []
          : [
              `Imported debugger observation ${observation.observation_id} has ${observation.completion} completion; runtime coverage remains partial even if every supplied event is correlated.`,
            ]),
        ...(observation.cleanup.status === "complete"
          ? []
          : [
              `Imported debugger observation ${observation.observation_id} has incomplete cleanup; remaining breakpoints and target run state require review.`,
            ]),
      ]),
    ],
  };
};

const sourceReferences = (
  input: ConsoleCorrelationInput,
  report: ConsoleCorrelationReport,
  reader: Reader,
): { retained: string[]; unverified: boolean } => {
  const records = new Map<string, Evidence | undefined>();
  const recordDigests = new Map<string, string>();
  const read = (id: string): Evidence | undefined => {
    if (!records.has(id)) {
      const record = reader?.(id);
      records.set(id, record?.evidence_id === id ? record : undefined);
    }
    return records.get(id);
  };
  const digestRecord = (record: Evidence): string => {
    let digest = recordDigests.get(record.evidence_id);
    if (digest === undefined) {
      digest = digestCanonicalValue(record.normalized_result);
      recordDigests.set(record.evidence_id, digest);
    }
    return digest;
  };
  const supplied = new Set<string>();
  const verified = new Set<string>();
  const rejectedReports = new Set<string>();
  const verifyReport = (
    id: string | undefined,
    operation: string,
    value: unknown,
  ): void => {
    if (id === undefined) return;
    supplied.add(id);
    const record = read(id);
    if (
      record?.operation === operation &&
      digestRecord(record) === digestCanonicalValue(value)
    )
      verified.add(id);
    else rejectedReports.add(id);
  };
  for (const capture of input.network_captures)
    verifyReport(
      capture.evidence_id,
      "inspect_console_network_capture",
      capture.report,
    );
  for (const observation of input.debugger_observations)
    verifyReport(
      observation.evidence_id,
      "observe_console_debugger",
      observation.report,
    );
  let unverified = rejectedReports.size > 0;
  for (const {
    event: { source },
  } of report.timeline) {
    const id = source.evidence_id;
    if (id === undefined) continue;
    supplied.add(id);
    const record = read(id);
    const matches =
      record !== undefined &&
      (record.subject?.digest.sha256 === source.artifact_sha256 ||
        ((record.operation === "observe_console_debugger" ||
          record.operation === "inspect_console_network_capture") &&
          digestRecord(record) === source.artifact_sha256));
    if (matches) verified.add(id);
    else unverified = true;
  }
  const retained = [...supplied].filter(
    (id) => verified.has(id) && !rejectedReports.has(id),
  );
  return {
    retained,
    unverified: unverified || retained.length !== supplied.size,
  };
};

const summarizeInput = (input: ConsoleCorrelationInput) =>
  jsonObjectSchema.parse({
    target: input.target,
    session_id: input.session_id,
    clocks: input.clocks,
    window_ns: input.window_ns,
    max_edges: input.max_edges,
    client_addresses: input.client_addresses,
    input_canonical_sha256: digestCanonicalValue(
      input,
      "Console correlation input",
    ),
    events_count: input.events.length,
    events_canonical_sha256: digestCanonicalValue(
      input.events,
      "Console events",
    ),
    network_captures: input.network_captures.map(
      ({ clock_id, report, evidence_id }) => ({
        clock_id,
        ...(evidence_id === undefined ? {} : { evidence_id }),
        artifact: report.artifact,
        format: report.format,
        packet_ordinals: report.packets.map(({ ordinal }) => ordinal),
        payload_release: report.coverage.payload_release,
        report_canonical_sha256: digestCanonicalValue(
          report,
          "Console capture report",
        ),
      }),
    ),
    debugger_observations: input.debugger_observations.map(
      ({ clock_id, report, evidence_id }) => ({
        clock_id,
        ...(evidence_id === undefined ? {} : { evidence_id }),
        observation_id: report.observation_id,
        provider: report.provider,
        endpoint: report.endpoint,
        target: report.target,
        completion: report.completion,
        failure: report.failure,
        cleanup: report.cleanup,
        stops_count: report.stops.length,
        report_canonical_sha256: digestCanonicalValue(
          report,
          "Console debugger report",
        ),
      }),
    ),
  });
