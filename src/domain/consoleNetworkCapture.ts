// MMA FILE SUMMARY
// Purpose: Defines provenance and coverage contracts for offline console packets and derived plaintext messages.
// Public interface: Capture input/report schemas, inferred types, and resource budgets.
// Collaborators: consoleNetworkMessages owns TCP/message contracts and source validation.
// Invariants: Packet timestamps remain exact or unknown; raw payload release is opt-in and message coverage is explicit.
import { createHash } from "node:crypto";
import { z } from "zod";
import { localPathStringSchema } from "./localPath.js";
import {
  CONSOLE_MESSAGE_LIMITS,
  consoleNetworkMessageSchema,
  consoleTcpStreamSchema,
  validateConsoleMessageSources,
} from "./consoleNetworkMessages.js";

export const CONSOLE_NETWORK_CAPTURE_LIMITS = {
  inputBytes: 32 * 1024 * 1024,
  outputBytes: 64 * 1024 * 1024,
  interfacesPerSection: 65_536,
} as const;

export const inspectConsoleNetworkCaptureInputSchema = z.strictObject({
  capture_path: localPathStringSchema.describe(
    "Absolute local pcap or pcapng file path; ingestion never contacts recorded endpoints.",
  ),
  packet_ordinals: z
    .array(z.number().int().nonnegative())
    .min(1)
    .optional()
    .describe(
      "Zero-based packet ordinals in caller-selected order; omit for all packets.",
    ),
  include_payload: z
    .boolean()
    .default(false)
    .describe(
      "Include retained TCP/UDP payload bytes as hex. Interpreted HTTP/DNS metadata and payload/body digests remain available by default; known credential headers are excluded from interpreted fields but raw packet hex is not automatically redacted.",
    ),
});

const count = z.number().int().nonnegative();
const decimal = z
  .string()
  .max(32)
  .regex(/^-?\d+$/u);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const endpoint = z.strictObject({
  address: z.string().min(1),
  port: count.max(65_535),
});

const consoleNetworkPacketValueSchema = z.strictObject({
  id: z.string().min(1),
  ordinal: count,
  offset: count.describe(
    "Byte offset of the enclosing packet record/block in the measured capture.",
  ),
  data_offset: count.describe(
    "Byte offset of captured link-layer bytes in the measured capture.",
  ),
  timestamp_ns: decimal
    .nullable()
    .describe(
      "Exact signed nanoseconds from the capture's declared clock origin; null when absent or finer than integral nanoseconds. Clock accuracy is not established.",
    ),
  timestamp_ticks: decimal.nullable(),
  timestamp_resolution: z
    .strictObject({
      base: z.union([z.literal(2), z.literal(10)]),
      exponent: count.max(127),
      offset_seconds: decimal,
    })
    .nullable(),
  captured_length: count,
  original_length: count,
  interface_id: z.string(),
  link_type: count,
  snap_length: count,
  network: z
    .strictObject({
      version: z.union([z.literal(4), z.literal(6)]),
      source: z.string(),
      destination: z.string(),
      protocol: count.max(255),
    })
    .nullable(),
  flow: z
    .strictObject({
      transport: z.enum(["tcp", "udp"]),
      source: endpoint,
      destination: endpoint,
    })
    .nullable(),
  tcp: z
    .strictObject({
      sequence: count.max(0xffff_ffff),
      acknowledgement: count.max(0xffff_ffff),
      flags: count.max(511),
    })
    .nullable(),
  fragmentation: z.strictObject({
    state: z.enum(["not_fragmented", "fragmented", "unknown"]),
    offset_bytes: count.nullable(),
    more_fragments: z.boolean().nullable(),
    identification: decimal.nullable(),
  }),
  truncated: z
    .boolean()
    .describe(
      "The record reports fewer captured bytes than original bytes; protocol-specific incompleteness is separately described in limitations.",
    ),
  encryption: z
    .enum(["unknown", "encrypted"])
    .describe(
      "Only explicit IP ESP is identified as encrypted; unrecognized or application-encrypted payloads remain unknown.",
    ),
  payload_state: z.enum(["available", "partial", "unavailable"]),
  payload_offset: count.nullable(),
  payload_bytes: count.nullable(),
  payload_sha256: digest.nullable(),
  payload_hex: z
    .string()
    .regex(/^[0-9a-f]*$/u)
    .refine((value) => value.length % 2 === 0, "Expected whole hex bytes.")
    .nullable(),
  limitations: z.array(z.string()),
});
type PacketContractFields = z.output<typeof consoleNetworkPacketValueSchema>;
type PacketIssue = (path: string, message: string) => void;
function validatePacketPayload(
  packet: PacketContractFields,
  issue: PacketIssue,
): void {
  const unavailable = packet.payload_state === "unavailable";
  if (
    unavailable !==
      (packet.payload_offset === null &&
        packet.payload_bytes === null &&
        packet.payload_sha256 === null) ||
    (unavailable && packet.payload_hex !== null)
  )
    issue(
      "payload_state",
      "Unavailable payloads have no bytes/digest/coordinate; available payloads require all three.",
    );
  if (
    !unavailable &&
    (packet.payload_offset === null ||
      packet.payload_bytes === null ||
      packet.payload_sha256 === null)
  )
    issue("payload_state", "Available payload metadata must be complete.");
  if (
    packet.payload_offset !== null &&
    packet.payload_bytes !== null &&
    (packet.payload_offset < packet.data_offset ||
      packet.payload_offset + packet.payload_bytes >
        packet.data_offset + packet.captured_length)
  )
    issue("payload_offset", "Payload extends outside captured packet bytes.");
  if (packet.payload_hex !== null) {
    const bytes = Buffer.from(packet.payload_hex, "hex");
    if (
      bytes.length !== packet.payload_bytes ||
      createHash("sha256").update(bytes).digest("hex") !== packet.payload_sha256
    )
      issue(
        "payload_hex",
        "Payload bytes disagree with their measured size or digest.",
      );
  }
}
function validatePacketTimestamp(
  packet: PacketContractFields,
  issue: PacketIssue,
): void {
  if (packet.timestamp_ticks === null) {
    if (packet.timestamp_ns !== null || packet.timestamp_resolution !== null)
      issue(
        "timestamp_ns",
        "An absent timestamp has no resolution or nanosecond projection.",
      );
  } else if (packet.timestamp_resolution === null)
    issue(
      "timestamp_resolution",
      "Raw ticks require their declared resolution.",
    );
  else {
    const resolution = packet.timestamp_resolution;
    const numerator = BigInt(packet.timestamp_ticks) * 1_000_000_000n;
    const denominator = BigInt(resolution.base) ** BigInt(resolution.exponent);
    const expected =
      numerator % denominator === 0n
        ? (
            numerator / denominator +
            BigInt(resolution.offset_seconds) * 1_000_000_000n
          ).toString()
        : null;
    if (packet.timestamp_ns !== expected)
      issue(
        "timestamp_ns",
        "Nanoseconds must exactly represent raw ticks and clock offset, or be null for subnanosecond fractions.",
      );
  }
}
export const consoleNetworkPacketSchema =
  consoleNetworkPacketValueSchema.superRefine((packet, context) => {
    const issue: PacketIssue = (path, message) =>
      context.addIssue({ code: "custom", path: [path], message });
    validatePacketPayload(packet, issue);
    if (packet.truncated !== packet.captured_length < packet.original_length)
      issue("truncated", "Truncation must match producer record lengths.");
    validatePacketTimestamp(packet, issue);
  });

export const consoleNetworkCaptureSchema = z
  .strictObject({
    artifact: z.strictObject({
      path: z.string(),
      sha256: digest,
      bytes: count,
    }),
    format: z.enum(["pcap", "pcapng"]),
    decoder: z.strictObject({
      id: z.literal("rea-native-pcap"),
      version: z.literal("1"),
    }),
    packets: z.array(consoleNetworkPacketSchema),
    messages: z
      .array(consoleNetworkMessageSchema)
      .max(CONSOLE_MESSAGE_LIMITS.messages)
      .default([]),
    tcp_streams: z
      .array(consoleTcpStreamSchema)
      .max(CONSOLE_MESSAGE_LIMITS.streams)
      .default([]),
    message_coverage: z
      .strictObject({
        scope: z.enum(["selected-packets", "not-attempted"]),
        http_messages: count,
        dns_messages: count,
        unknown_tcp_directions: count,
        unknown_udp_datagrams: count,
      })
      .default({
        scope: "not-attempted",
        http_messages: 0,
        dns_messages: 0,
        unknown_tcp_directions: 0,
        unknown_udp_datagrams: 0,
      }),
    coverage: z.strictObject({
      container: z.literal("complete"),
      total_packets: count,
      selected_packets: count,
      unknown_blocks: count,
      truncated_packets: count,
      fragmented_packets: count,
      unsupported_link_packets: count,
      payload_release: z.enum(["digest_only", "hex"]),
      reassembly: z.enum(["not_attempted", "bounded-selected-tcp"]),
      decryption: z.literal("not_attempted"),
    }),
    limitations: z.array(z.string()),
  })
  .superRefine((capture, context) => {
    validateConsoleMessageSources(capture, context);
    const issue = (path: (string | number)[], message: string): void =>
      context.addIssue({ code: "custom", path, message });
    if (
      capture.coverage.selected_packets !== capture.packets.length ||
      capture.coverage.selected_packets > capture.coverage.total_packets
    )
      issue(
        ["coverage", "selected_packets"],
        "Selected counts must match unique returned packet records.",
      );
    const ordinals = new Set<number>();
    for (const [index, packet] of capture.packets.entries()) {
      if (
        ordinals.has(packet.ordinal) ||
        packet.ordinal >= capture.coverage.total_packets
      )
        issue(
          ["packets", index, "ordinal"],
          "Packet ordinal is duplicate or outside capture coverage.",
        );
      ordinals.add(packet.ordinal);
      if (
        packet.id !==
        `sha256:${capture.artifact.sha256}/packet:${packet.ordinal}`
      )
        issue(
          ["packets", index, "id"],
          "Packet identity must bind to this measured artifact and ordinal.",
        );
      if (
        packet.offset >= packet.data_offset ||
        packet.data_offset + packet.captured_length > capture.artifact.bytes
      )
        issue(
          ["packets", index, "data_offset"],
          "Packet coordinates must fall within the measured capture.",
        );
      if (
        capture.coverage.payload_release === "digest_only" &&
        packet.payload_hex !== null
      )
        issue(
          ["packets", index, "payload_hex"],
          "Digest-only policy must not release payload bytes.",
        );
    }
    for (const field of [
      "truncated_packets",
      "fragmented_packets",
      "unsupported_link_packets",
    ] as const)
      if (capture.coverage[field] > capture.coverage.total_packets)
        issue(
          ["coverage", field],
          "Packet coverage count exceeds total packet records.",
        );
  });

export type InspectConsoleNetworkCaptureInput = z.input<
  typeof inspectConsoleNetworkCaptureInputSchema
>;
export type ConsoleNetworkPacket = z.infer<typeof consoleNetworkPacketSchema>;
export type ConsoleNetworkCapture = z.infer<typeof consoleNetworkCaptureSchema>;
