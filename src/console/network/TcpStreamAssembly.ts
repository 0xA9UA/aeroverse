// MMA FILE SUMMARY
// Purpose: Reconstructs bounded selected TCP byte ranges with explicit gaps, overlap conflicts and generations.
// Public interface: assembleTcpStreams() and packet/chunk provenance types.
// Collaborators: Packet metadata, private payload views and console message contracts.
// Invariants: Interfaces/generations stay distinct; incomplete FIN payloads and conflicting bytes cannot establish complete messages.
import { createHash } from "node:crypto";
import { AnalysisResourceConstraintError } from "../../domain/analysisErrorCore.js";
import type { ConsoleNetworkPacket } from "../../domain/consoleNetworkCapture.js";
import {
  CONSOLE_MESSAGE_LIMITS,
  type ConsoleTcpStream,
} from "../../domain/consoleNetworkMessages.js";

export interface PacketPayload {
  packet: ConsoleNetworkPacket;
  payload: Buffer | null;
}
export interface TcpSourceSpan {
  offset: number;
  bytes: number;
  payload_offset: number;
  packet: ConsoleNetworkPacket;
}
export interface TcpChunk {
  offset: number;
  bytes: Buffer;
  sources: TcpSourceSpan[];
}
export interface AssembledTcpStream {
  report: ConsoleTcpStream;
  chunks: TcpChunk[];
}
type Segment = PacketPayload & { offset: number };
type Direction = {
  report: ConsoleTcpStream;
  anchor: number;
  segments: Segment[];
  partial: boolean;
  finOffset: number | null;
};
type Connection = {
  id: string;
  generation: number;
  basis: ConsoleTcpStream["generation_basis"];
  directions: Map<string, Direction>;
  syn: Map<string, number>;
  fin: Set<string>;
  closed: boolean;
};
const modulo = 0x1_0000_0000;
const sequence = (value: number): number =>
  ((value % modulo) + modulo) % modulo;
const distance = (value: number, anchor: number): number => {
  const difference = sequence(value - anchor);
  return difference >= 0x8000_0000 ? difference - modulo : difference;
};
const identity = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const capacity = (reason: string): never => {
  throw new AnalysisResourceConstraintError(
    "inspect_console_network_capture",
    "memory",
    reason,
    CONSOLE_MESSAGE_LIMITS,
  );
};

/** Capture ordinal establishes control-packet order; sequence numbers establish data byte order. */
export const assembleTcpStreams = (
  packets: readonly PacketPayload[],
): AssembledTcpStream[] => {
  const active = new Map<string, Connection>();
  const generations = new Map<string, number>();
  const directions: Direction[] = [];
  let segmentCount = 0;
  for (const item of [...packets].sort(
    (a, b) => a.packet.ordinal - b.packet.ordinal,
  )) {
    const { packet } = item;
    if (packet.flow?.transport !== "tcp" || packet.tcp === null) continue;
    const endpoints = [packet.flow.source, packet.flow.destination].map(
      (endpoint) => JSON.stringify(endpoint),
    );
    const directionId = endpoints.join("->");
    const connectionKey = JSON.stringify([
      packet.interface_id,
      [...endpoints].sort(),
    ]);
    const syn = (packet.tcp.flags & 2) !== 0,
      ack = (packet.tcp.flags & 16) !== 0;
    const connection = selectConnection(active, generations, {
      connectionKey,
      directionId,
      syn,
      ack,
      sequenceNumber: packet.tcp.sequence,
    });
    let direction = connection.directions.get(directionId);
    if (direction === undefined) {
      if (directions.length >= CONSOLE_MESSAGE_LIMITS.streams)
        capacity("Selected TCP directions exceed the bounded stream capacity.");
      direction = newDirection(connection, packet);
      connection.directions.set(directionId, direction);
      directions.push(direction);
    }
    direction.report.packet_ids.push(packet.id);
    if (syn) direction.report.initial_boundary = "syn-observed";
    segmentCount = recordPayload(direction, item, segmentCount);
    recordControl(direction, connection, { ...item, directionId });
  }
  return directions.map(assembleDirection);
};

const selectConnection = (
  active: Map<string, Connection>,
  generations: Map<string, number>,
  input: {
    connectionKey: string;
    directionId: string;
    syn: boolean;
    ack: boolean;
    sequenceNumber: number;
  },
): Connection => {
  const { connectionKey, directionId, syn, ack, sequenceNumber } = input;
  let connection = active.get(connectionKey);
  if (
    connection === undefined ||
    connection.closed ||
    (syn &&
      replacesDirectionHandshake(connection, {
        directionId,
        sequenceNumber,
        ack,
      }))
  ) {
    const generation = (generations.get(connectionKey) ?? -1) + 1;
    generations.set(connectionKey, generation);
    connection = {
      id: `tcp:${identity([connectionKey, generation])}`,
      generation,
      basis: syn ? "syn-observed" : "midstream-unknown",
      directions: new Map(),
      syn: new Map(),
      fin: new Set(),
      closed: false,
    };
    active.set(connectionKey, connection);
  }
  if (syn) connection.syn.set(directionId, sequenceNumber);
  return connection;
};

const replacesDirectionHandshake = (
  connection: Connection,
  input: { directionId: string; sequenceNumber: number; ack: boolean },
): boolean => {
  const { directionId, sequenceNumber, ack } = input;
  const previous = connection.syn.get(directionId);
  // A first peer SYN joins the handshake; an established direction without
  // its initial SYN cannot safely bind a newly observed handshake to old data.
  return previous === undefined
    ? !ack ||
        connection.directions.has(directionId) ||
        connection.syn.size === 0
    : previous !== sequenceNumber;
};

const recordPayload = (
  direction: Direction,
  item: PacketPayload,
  segmentCount: number,
): number => {
  const { packet, payload } = item;
  const tcp = packet.tcp;
  if (tcp === null) return segmentCount;
  direction.partial ||=
    packet.payload_state !== "available" ||
    packet.fragmentation.state !== "not_fragmented";
  const syn = (tcp.flags & 2) !== 0;
  if (payload !== null && payload.length > 0) {
    if (++segmentCount > CONSOLE_MESSAGE_LIMITS.segments)
      capacity("Selected TCP segments exceed the reassembly capacity.");
    direction.segments.push({
      ...item,
      offset: distance(
        sequence(tcp.sequence + (syn ? 1 : 0)),
        direction.anchor,
      ),
    });
  }
  return segmentCount;
};

const recordControl = (
  direction: Direction,
  connection: Connection,
  input: PacketPayload & { directionId: string },
): void => {
  const { packet, payload, directionId } = input;
  const tcp = packet.tcp;
  if (tcp === null) return;
  const syn = (tcp.flags & 2) !== 0;
  if ((tcp.flags & 1) !== 0) {
    direction.report.final_boundary = "fin-observed";
    const completePayload =
      packet.payload_state === "available" &&
      packet.fragmentation.state === "not_fragmented" &&
      payload !== null;
    direction.report.final_sequence = completePayload
      ? sequence(tcp.sequence + (syn ? 1 : 0) + payload.length)
      : null;
    direction.finOffset =
      direction.report.final_sequence === null
        ? null
        : distance(direction.report.final_sequence, direction.anchor);
    connection.fin.add(directionId);
  }
  if ((tcp.flags & 4) !== 0) {
    direction.report.final_boundary = "rst-observed";
    connection.closed = true;
  }
  if (connection.fin.size === 2) connection.closed = true;
};

const newDirection = (
  connection: Connection,
  packet: ConsoleNetworkPacket,
): Direction => {
  if (packet.flow === null || packet.tcp === null)
    throw new Error("TCP direction requires decoded flow and sequence");
  const anchor = sequence(
    packet.tcp.sequence + ((packet.tcp.flags & 2) !== 0 ? 1 : 0),
  );
  return {
    anchor,
    segments: [],
    partial: false,
    finOffset: null,
    report: {
      id: `${connection.id}/direction:${identity(packet.flow)}`,
      connection_id: connection.id,
      generation: connection.generation,
      generation_basis: connection.basis,
      interface_id: packet.interface_id,
      flow: packet.flow,
      packet_ids: [],
      first_sequence: anchor,
      retained_bytes: 0,
      agreeing_retransmitted_bytes: 0,
      conflicting_overlap_bytes: 0,
      missing_ranges: [],
      initial_boundary: "unknown",
      final_boundary: "unknown",
      final_sequence: null,
      final_boundary_contiguous: false,
      status: "contiguous",
      limitations: [
        "Reassembly covers selected packets on one capture interface; checksum validity, peer receipt and complete session capture are not established.",
        ...(connection.basis === "midstream-unknown"
          ? [
              "No initial SYN was observed; connection generation and preceding bytes are unknown, so repeated 5-tuples may refer to different connections.",
            ]
          : []),
      ],
    },
  };
};

const assembleDirection = (direction: Direction): AssembledTcpStream => {
  const { report } = direction;
  const segments = direction.segments
    .filter(
      (item): item is Segment & { payload: Buffer } => item.payload !== null,
    )
    .sort((a, b) => a.offset - b.offset || a.packet.ordinal - b.packet.ordinal);
  if (segments.length === 0)
    return direction.partial
      ? unsupportedDirection(report)
      : { report, chunks: [] };
  const first = segments[0]!.offset;
  const base = report.initial_boundary === "syn-observed" ? 0 : first;
  const end = segments.reduce(
    (maximum, item) => Math.max(maximum, item.offset + item.payload.length),
    first,
  );
  report.first_sequence = sequence(direction.anchor + base);
  if (unsupportedSequenceSpan(direction, { first, base, end })) {
    return unsupportedDirection(report);
  }
  const ranges: { start: number; end: number }[] = [];
  for (const item of segments) {
    const last = ranges.at(-1),
      stop = item.offset + item.payload.length;
    if (last === undefined || item.offset > last.end)
      ranges.push({ start: item.offset, end: stop });
    else last.end = Math.max(last.end, stop);
  }
  const chunks = fillChunks(segments, ranges, base, report);
  report.retained_bytes = chunks.reduce(
    (total, chunk) => total + chunk.bytes.length,
    0,
  );
  if (first > base)
    report.missing_ranges.push({ offset: 0, bytes: first - base });
  for (let index = 1; index < ranges.length; index++)
    report.missing_ranges.push({
      offset: ranges[index - 1]!.end - base,
      bytes: ranges[index]!.start - ranges[index - 1]!.end,
    });
  if (direction.finOffset !== null && direction.finOffset > end)
    report.missing_ranges.push({
      offset: end - base,
      bytes: direction.finOffset - end,
    });
  report.final_boundary_contiguous =
    direction.finOffset === end && report.conflicting_overlap_bytes === 0;
  report.status =
    report.conflicting_overlap_bytes > 0
      ? "conflicting"
      : report.missing_ranges.length > 0
        ? "gapped"
        : "contiguous";
  if (report.status === "conflicting")
    report.limitations.push(
      "Overlapping segments disagree; no application messages are decoded from this direction.",
    );
  if (report.status === "gapped")
    report.limitations.push(
      "Missing sequence ranges separate retained chunks; no message is reconstructed across a gap.",
    );
  return { report, chunks: report.status === "conflicting" ? [] : chunks };
};

const unsupportedDirection = (report: ConsoleTcpStream): AssembledTcpStream => {
  report.status = "unsupported";
  report.limitations.push(
    "Partial/fragmented data, pre-SYN sequence inconsistency or an excessive sequence span prevents trustworthy stream interpretation.",
  );
  return { report, chunks: [] };
};

const unsupportedSequenceSpan = (
  direction: Direction,
  span: { first: number; base: number; end: number },
): boolean =>
  span.end - span.base > CONSOLE_MESSAGE_LIMITS.streamBytes ||
  direction.partial ||
  span.first < span.base ||
  (direction.finOffset !== null && direction.finOffset < span.end);

const fillChunks = (
  segments: readonly (Segment & { payload: Buffer })[],
  ranges: readonly { start: number; end: number }[],
  base: number,
  report: ConsoleTcpStream,
): TcpChunk[] => {
  const chunks = ranges.map((range) => ({
    offset: range.start - base,
    bytes: Buffer.alloc(range.end - range.start),
    sources: [] as TcpSourceSpan[],
  }));
  let rangeIndex = 0,
    writtenEnd = ranges[0]!.start;
  for (const item of segments) {
    while (
      item.offset >= ranges[rangeIndex]!.end &&
      rangeIndex + 1 < ranges.length
    ) {
      rangeIndex++;
      writtenEnd = ranges[rangeIndex]!.start;
    }
    const range = ranges[rangeIndex]!,
      chunk = chunks[rangeIndex]!;
    const overlap = Math.max(
      0,
      Math.min(writtenEnd - item.offset, item.payload.length),
    );
    for (let index = 0; index < overlap; index++) {
      if (
        chunk.bytes[item.offset - range.start + index] === item.payload[index]
      )
        report.agreeing_retransmitted_bytes++;
      else report.conflicting_overlap_bytes++;
    }
    if (overlap < item.payload.length) {
      item.payload.copy(
        chunk.bytes,
        item.offset - range.start + overlap,
        overlap,
      );
      chunk.sources.push({
        offset: item.offset - base + overlap,
        bytes: item.payload.length - overlap,
        payload_offset: overlap,
        packet: item.packet,
      });
      writtenEnd = Math.max(writtenEnd, item.offset + item.payload.length);
    }
  }
  return chunks;
};
