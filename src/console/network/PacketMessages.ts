// MMA FILE SUMMARY
// Purpose: Interprets selected packet payloads into source-bound plaintext HTTP/DNS evidence.
// Public interface: inspectPacketMessages().
// Collaborators: TCP sequence assembly, HTTP framing, UDP DNS decoding and canonical message schemas.
// Invariants: Exact source ranges accompany messages; no IP reassembly, TLS decryption or cross-gap reconstruction.
import { createHash } from "node:crypto";
import { AnalysisResourceConstraintError } from "../../domain/analysisErrorCore.js";
import {
  CONSOLE_MESSAGE_LIMITS,
  type ConsoleHttpMessage,
  type ConsoleDnsMessage,
  type ConsoleNetworkMessage,
} from "../../domain/consoleNetworkMessages.js";
import {
  assembleTcpStreams,
  type AssembledTcpStream,
  type PacketPayload,
  type TcpChunk,
} from "./TcpStreamAssembly.js";
import { decodeHttpMessages, type ParsedHttpMessage } from "./HttpMessages.js";
import { decodeDnsDatagram } from "./DnsMessages.js";

const capacity = (): never => {
  throw new AnalysisResourceConstraintError(
    "inspect_console_network_capture",
    "memory",
    "Selected plaintext messages exceed the bounded interpretation capacity; select fewer packet ordinals.",
    CONSOLE_MESSAGE_LIMITS,
  );
};
const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

export const inspectPacketMessages = (
  packets: readonly PacketPayload[],
  outputBudgetBytes = 64 * 1024 * 1024,
) => {
  const assembled = assembleTcpStreams(packets);
  const messages: ConsoleNetworkMessage[] = [];
  let outputBytes = 512;
  const account = (value: unknown): void => {
    outputBytes += Buffer.byteLength(JSON.stringify(value)) + 1;
    if (outputBytes > outputBudgetBytes)
      throw new AnalysisResourceConstraintError(
        "inspect_console_network_capture",
        "transport",
        "Derived message/stream metadata exceeds the remaining output budget; select fewer packet ordinals.",
        { available_output_bytes: outputBudgetBytes },
      );
  };
  for (const stream of assembled) account(stream.report);
  const append = (message: ConsoleNetworkMessage): void => {
    if (messages.length >= CONSOLE_MESSAGE_LIMITS.messages) capacity();
    account(message);
    messages.push(message);
  };
  let unknownTcp = 0,
    unknownUdp = 0;
  for (const stream of assembled) {
    if (
      !inspectHttpStream(stream, append) &&
      (stream.report.retained_bytes > 0 ||
        stream.report.status === "unsupported")
    )
      unknownTcp++;
  }
  for (const item of packets) {
    if (item.packet.flow?.transport !== "udp" || item.payload === null)
      continue;
    const message = inspectDnsPacket(item);
    if (message === null) unknownUdp++;
    else append(message);
  }
  return {
    tcp_streams: assembled.map(({ report }) => report),
    messages,
    message_coverage: {
      scope: "selected-packets" as const,
      http_messages: messages.filter(({ protocol }) => protocol === "http")
        .length,
      dns_messages: messages.filter(({ protocol }) => protocol === "dns")
        .length,
      unknown_tcp_directions: unknownTcp,
      unknown_udp_datagrams: unknownUdp,
    },
  };
};

const inspectHttpStream = (
  stream: AssembledTcpStream,
  append: (message: ConsoleNetworkMessage) => void,
): boolean => {
  let found = false;
  for (const chunk of stream.chunks) {
    const parsed = decodeHttpMessages(
      chunk.bytes,
      stream.report.final_boundary === "fin-observed" &&
        stream.report.final_boundary_contiguous &&
        chunk === stream.chunks.at(-1),
    );
    if (
      parsed.length === CONSOLE_MESSAGE_LIMITS.messages &&
      parsed.at(-1)!.offset + parsed.at(-1)!.bytes < chunk.bytes.length
    )
      capacity();
    for (const message of parsed) {
      const sources = messageSources(chunk, message);
      append({
        protocol: "http",
        id: `${stream.report.id}/http:${chunk.offset + message.offset}`,
        flow: stream.report.flow,
        interface_id: stream.report.interface_id,
        connection_id: stream.report.connection_id,
        stream_id: stream.report.id,
        stream_offset: chunk.offset + message.offset,
        status: message.status,
        bytes: message.bytes,
        wire_sha256: message.wire_sha256,
        packet_ids: [...new Set(sources.map(({ packet_id }) => packet_id))],
        sources,
        http: message.http,
        limitations: [...stream.report.limitations, ...message.limitations],
      });
      found = true;
    }
  }
  return found;
};

const inspectDnsPacket = (item: PacketPayload): ConsoleDnsMessage | null => {
  if (item.packet.flow?.transport !== "udp" || item.payload === null)
    return null;
  if (
    ![item.packet.flow.source.port, item.packet.flow.destination.port].includes(
      53,
    )
  ) {
    return null;
  }
  const parsed = decodeDnsDatagram(item.payload);
  if (parsed === null) {
    return null;
  }
  const completePayload =
    item.packet.payload_state === "available" &&
    item.packet.fragmentation.state === "not_fragmented";
  return {
    protocol: "dns",
    id: `${item.packet.id}/dns`,
    flow: item.packet.flow,
    interface_id: item.packet.interface_id,
    connection_id: null,
    stream_id: null,
    stream_offset: null,
    status: completePayload ? parsed.status : "incomplete",
    bytes: item.payload.length,
    wire_sha256: sha256(item.payload),
    packet_ids: [item.packet.id],
    sources:
      item.packet.payload_offset === null
        ? []
        : [
            {
              packet_id: item.packet.id,
              file_offset: item.packet.payload_offset,
              bytes: item.payload.length,
              message_offset: 0,
            },
          ],
    dns: parsed.dns,
    limitations: [
      ...item.packet.limitations,
      ...parsed.limitations,
      ...(completePayload
        ? []
        : [
            "The retained UDP payload is partial or fragmented; no complete DNS message is established.",
          ]),
    ],
  };
};

const messageSources = (
  chunk: TcpChunk,
  message: ParsedHttpMessage,
): ConsoleHttpMessage["sources"] => {
  const start = chunk.offset + message.offset,
    end = start + message.bytes;
  const sources: ConsoleHttpMessage["sources"] = [];
  let left = 0,
    right = chunk.sources.length;
  while (left < right) {
    const mid = Math.floor((left + right) / 2),
      span = chunk.sources[mid]!;
    if (span.offset + span.bytes <= start) left = mid + 1;
    else right = mid;
  }
  for (let index = left; index < chunk.sources.length; index++) {
    const span = chunk.sources[index]!;
    if (span.offset >= end) break;
    const first = Math.max(start, span.offset),
      last = Math.min(end, span.offset + span.bytes);
    if (first >= last || span.packet.payload_offset === null) continue;
    sources.push({
      packet_id: span.packet.id,
      file_offset:
        span.packet.payload_offset + span.payload_offset + first - span.offset,
      bytes: last - first,
      message_offset: first - start,
    });
  }
  return sources;
};
