// MMA FILE SUMMARY
// Purpose: Projects decoded network messages into compact, source-bound correlation events.
// Public interface: networkMessageEvent().
// Collaborators: Capture/message contracts and canonical event schema.
// Invariants: Source pointers identify the retained report; message timing uses all source packets without inventing causal parents.
import type {
  ConsoleNetworkCapture,
  ConsoleNetworkPacket,
} from "./consoleNetworkCapture.js";
import type { ConsoleNetworkMessage } from "./consoleNetworkMessages.js";
import type {
  ConsoleCorrelationInput,
  ConsoleObservationEvent,
} from "./consoleObservation.js";

export const networkMessageEvent = (
  context: {
    input: ConsoleCorrelationInput;
    clockId: string;
    report: ConsoleNetworkCapture;
    reportDigest: string;
    packets: ReadonlyMap<string, ConsoleNetworkPacket>;
  },
  message: ConsoleNetworkMessage,
  index: number,
): ConsoleObservationEvent => {
  const { input, clockId, report, reportDigest, packets } = context;
  const timestamps = message.packet_ids.map(
    (id) => packets.get(id)?.timestamp_ns ?? null,
  );
  const timestamp =
    timestamps.length === 0 || timestamps.some((value) => value === null)
      ? null
      : timestamps.reduce<string | null>(
          (earliest, value) =>
            value !== null &&
            (earliest === null || BigInt(value) < BigInt(earliest))
              ? value
              : earliest,
          null,
        );
  const metadata: NonNullable<ConsoleObservationEvent["network_message"]> =
    message.protocol === "http"
      ? {
          protocol: "http",
          status: message.status,
          kind: message.http.kind,
          method: message.http.method,
          target: message.http.target,
          status_code: message.http.status_code,
        }
      : {
          protocol: "dns",
          status: message.status,
          query: message.dns.query,
          question_names: message.dns.questions
            .slice(0, 16)
            .map(({ name }) => name),
        };
  const label =
    message.protocol === "http"
      ? `HTTP ${message.http.kind}: ${message.http.method ?? message.http.status_code ?? "unknown"} ${(message.http.target ?? "").slice(0, 256)}`
      : `DNS ${message.dns.query ? "query" : "response"}: ${message.dns.questions
          .slice(0, 2)
          .map(({ name }) => name)
          .join(", ")}`;
  return {
    event_id: message.id,
    session_id: input.session_id,
    game_sha256: input.target.game_sha256,
    kind: "network",
    label,
    clock_id: clockId,
    timestamp_ns: timestamp,
    source: { artifact_sha256: reportDigest, locator: `/messages/${index}` },
    flow: {
      ...message.flow,
      ...(message.connection_id === null
        ? {}
        : { connection_id: message.connection_id }),
    },
    network_message: metadata,
    payload: {
      sha256: message.wire_sha256,
      bytes: message.bytes,
      complete: message.status === "complete",
      representation: "decoded-message",
    },
    limitations: [
      ...report.limitations,
      ...message.limitations,
      "Session and game association are caller-declared; message decoding does not authenticate the runtime/game binding.",
      "Message timestamp is the earliest source-packet timestamp, not the application call time; packet parents and request/response pairing are not inferred.",
      ...(message.protocol === "dns" && message.dns.questions.length > 16
        ? [
            "The compact event includes the first 16 DNS question names; retain the source report for all decoded questions.",
          ]
        : []),
    ],
  };
};
