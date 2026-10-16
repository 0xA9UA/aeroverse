// MMA FILE SUMMARY
// Purpose: Defines derived plaintext messages and bounded TCP coverage with exact packet provenance.
// Public interface: Message/stream schemas, inferred types and interpretation resource limits.
// Invariants: Message completeness is distinct from session completeness; unique packet IDs exactly match byte-source membership.
import { createHash } from "node:crypto";
import { z } from "zod";
import type { ConsoleNetworkPacket } from "./consoleNetworkCapture.js";

export const CONSOLE_MESSAGE_LIMITS = {
  streams: 4096,
  segments: 100_000,
  messages: 4096,
  streamBytes: 32 * 1024 * 1024,
  headerBytes: 64 * 1024,
  dnsRecords: 4096,
} as const;
const count = z.number().int().nonnegative();
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const endpoint = z.strictObject({
  address: z.string(),
  port: count.max(65535),
});
export const consoleMessageFlowSchema = z.strictObject({
  transport: z.enum(["tcp", "udp"]),
  source: endpoint,
  destination: endpoint,
});
const source = z.strictObject({
  packet_id: z.string(),
  file_offset: count,
  bytes: count,
  message_offset: count.describe(
    "Byte position in the retained message wire representation.",
  ),
});
const messageBase = z.strictObject({
  id: z.string(),
  flow: consoleMessageFlowSchema,
  interface_id: z.string(),
  connection_id: z.string().nullable(),
  stream_id: z.string().nullable(),
  stream_offset: count.nullable(),
  status: z.enum(["complete", "incomplete", "unsupported", "invalid"]),
  bytes: count,
  wire_sha256: digest,
  packet_ids: z.array(z.string()),
  sources: z.array(source),
  limitations: z.array(z.string()),
});
export const consoleHttpMessageSchema = messageBase.extend({
  protocol: z.literal("http"),
  http: z.strictObject({
    kind: z.enum(["request", "response"]),
    version: z.enum(["HTTP/1.0", "HTTP/1.1"]),
    method: z.string().nullable(),
    target: z.string().nullable(),
    status_code: count.nullable(),
    headers: z.array(
      z.strictObject({
        name: z.string(),
        value: z.string().nullable(),
        redacted: z.boolean(),
      }),
    ),
    framing: z.enum([
      "content-length",
      "no-body",
      "close-delimited",
      "unsupported",
      "unknown",
    ]),
    body: z.strictObject({
      bytes: count,
      sha256: digest,
      complete: z.boolean(),
      representation: z.literal("transfer-payload"),
    }),
  }),
});
export const consoleDnsMessageSchema = messageBase.extend({
  protocol: z.literal("dns"),
  dns: z.strictObject({
    transaction_id: count.max(65535),
    query: z.boolean(),
    truncated_flag: z.boolean(),
    rcode: count.max(15),
    questions: z.array(
      z.strictObject({
        name: z.string(),
        type: count.max(65535),
        class: count.max(65535),
      }),
    ),
    records: z.array(
      z.strictObject({
        section: z.enum(["answer", "authority", "additional"]),
        name: z.string(),
        type: count.max(65535),
        class: count.max(65535),
        ttl: count,
        rdata_sha256: digest,
        address: z.string().nullable(),
        target: z.string().nullable(),
      }),
    ),
  }),
});
export const consoleNetworkMessageSchema = z.discriminatedUnion("protocol", [
  consoleHttpMessageSchema,
  consoleDnsMessageSchema,
]);

export const consoleTcpStreamSchema = z.strictObject({
  id: z.string(),
  connection_id: z.string(),
  generation: count,
  generation_basis: z.enum(["syn-observed", "midstream-unknown"]),
  interface_id: z.string(),
  flow: consoleMessageFlowSchema,
  packet_ids: z.array(z.string()),
  first_sequence: count.max(0xffff_ffff),
  retained_bytes: count,
  agreeing_retransmitted_bytes: count,
  conflicting_overlap_bytes: count,
  missing_ranges: z.array(z.strictObject({ offset: count, bytes: count })),
  initial_boundary: z.enum(["syn-observed", "unknown"]),
  final_boundary: z.enum(["fin-observed", "rst-observed", "unknown"]),
  final_sequence: count.max(0xffff_ffff).nullable(),
  final_boundary_contiguous: z.boolean(),
  status: z.enum(["contiguous", "gapped", "conflicting", "unsupported"]),
  limitations: z.array(z.string()),
});

export type ConsoleNetworkMessage = z.output<
  typeof consoleNetworkMessageSchema
>;
export type ConsoleHttpMessage = z.output<typeof consoleHttpMessageSchema>;
export type ConsoleDnsMessage = z.output<typeof consoleDnsMessageSchema>;
export type ConsoleTcpStream = z.output<typeof consoleTcpStreamSchema>;

type MessageSourceCapture = {
  artifact: { bytes: number };
  packets: readonly ConsoleNetworkPacket[];
  messages: readonly ConsoleNetworkMessage[];
  tcp_streams: readonly ConsoleTcpStream[];
};
type MessageIssue = (path: (string | number)[], message: string) => void;
type MessageSourceState = {
  packets: ReadonlyMap<string, ConsoleNetworkPacket>;
  released: Map<string, Buffer>;
  artifactBytes: number;
};
type MessageRange = z.output<typeof source>;
type PacketPayloadCoordinates = ConsoleNetworkPacket & {
  payload_offset: number;
  payload_bytes: number;
};
function validMessageSource(
  range: MessageRange,
  packet: ConsoleNetworkPacket | undefined,
  position: {
    cursor: number;
    message: ConsoleNetworkMessage;
    artifactBytes: number;
  },
): packet is PacketPayloadCoordinates {
  return (
    range.message_offset === position.cursor &&
    range.bytes !== 0 &&
    packet?.payload_offset != null &&
    packet.payload_bytes !== null &&
    packet.interface_id === position.message.interface_id &&
    JSON.stringify(packet.flow) === JSON.stringify(position.message.flow) &&
    range.file_offset >= packet.payload_offset &&
    range.file_offset + range.bytes <=
      packet.payload_offset + packet.payload_bytes &&
    range.file_offset + range.bytes <= position.artifactBytes
  );
}
function validateMessageRanges(
  message: ConsoleNetworkMessage,
  index: number,
  state: MessageSourceState,
  issue: MessageIssue,
): void {
  let cursor = 0,
    rawAvailable = true;
  const hash = createHash("sha256"),
    used = new Set<string>();
  for (const [sourceIndex, source] of message.sources.entries()) {
    const packet = state.packets.get(source.packet_id);
    used.add(source.packet_id);
    if (
      !validMessageSource(source, packet, {
        cursor,
        message,
        artifactBytes: state.artifactBytes,
      })
    ) {
      issue(
        ["messages", index, "sources", sourceIndex],
        "Message sources must cover consecutive bytes inside selected packet payloads.",
      );
      rawAvailable = false;
    } else if (packet.payload_hex === null) rawAvailable = false;
    else {
      let bytes = state.released.get(packet.id);
      if (bytes === undefined) {
        bytes = Buffer.from(packet.payload_hex, "hex");
        state.released.set(packet.id, bytes);
      }
      const offset = source.file_offset - packet.payload_offset;
      hash.update(bytes.subarray(offset, offset + source.bytes));
    }
    cursor += source.bytes;
  }
  const declared = new Set(message.packet_ids);
  if (
    cursor !== message.bytes ||
    declared.size !== message.packet_ids.length ||
    declared.size !== used.size ||
    [...used].some((id) => !declared.has(id))
  )
    issue(
      ["messages", index, "sources"],
      "Message lengths and packet identities must agree with their exact source ranges.",
    );
  if (rawAvailable && hash.digest("hex") !== message.wire_sha256)
    issue(
      ["messages", index, "wire_sha256"],
      "Released packet bytes disagree with the message wire digest.",
    );
}
function validateMessageSemantics(
  message: ConsoleNetworkMessage,
  index: number,
  issue: MessageIssue,
): void {
  if (
    message.protocol === "http" &&
    (message.http.body.bytes > message.bytes ||
      (message.status === "complete" && !message.http.body.complete))
  )
    issue(
      ["messages", index, "http", "body"],
      "Complete HTTP messages require complete bounded bodies.",
    );
  if (
    (message.protocol === "http" && message.flow.transport !== "tcp") ||
    (message.protocol === "dns" && message.flow.transport !== "udp")
  )
    issue(
      ["messages", index, "flow"],
      "Interpreted protocol transport must match this decoder's supported framing.",
    );
  if (
    message.protocol === "dns" &&
    message.status === "complete" &&
    message.dns.truncated_flag
  )
    issue(
      ["messages", index, "status"],
      "Truncated DNS replies cannot establish complete answer coverage.",
    );
}
function validateStreamSources(
  streams: readonly ConsoleTcpStream[],
  packets: ReadonlyMap<string, ConsoleNetworkPacket>,
  issue: MessageIssue,
): void {
  for (const [index, stream] of streams.entries()) {
    if (
      stream.flow.transport !== "tcp" ||
      stream.packet_ids.some((id) => {
        const packet = packets.get(id);
        return (
          packet === undefined ||
          packet.interface_id !== stream.interface_id ||
          JSON.stringify(packet.flow) !== JSON.stringify(stream.flow)
        );
      })
    )
      issue(
        ["tcp_streams", index, "packet_ids"],
        "TCP coverage must refer to selected packets on its declared interface and direction.",
      );
  }
}
/** Validate source ranges independently of the protocol adapter, including raw bytes when released. */
export const validateConsoleMessageSources = (
  capture: MessageSourceCapture,
  context: z.RefinementCtx,
): void => {
  const state: MessageSourceState = {
    packets: new Map(capture.packets.map((packet) => [packet.id, packet])),
    released: new Map(),
    artifactBytes: capture.artifact.bytes,
  };
  const issue: MessageIssue = (path, message) =>
    context.addIssue({ code: "custom", path, message });
  const ids = new Set<string>();
  for (const [index, message] of capture.messages.entries()) {
    if (ids.has(message.id))
      issue(["messages", index, "id"], "Message IDs must be unique.");
    ids.add(message.id);
    validateMessageRanges(message, index, state, issue);
    validateMessageSemantics(message, index, issue);
  }
  validateStreamSources(capture.tcp_streams, state.packets, issue);
};
