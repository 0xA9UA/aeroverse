// MMA FILE SUMMARY
// Purpose: Walks validated pcap/pcapng record boundaries without copying packet bytes.
// Public interface: openCaptureContainer(), CaptureRecord, CaptureContainerFailure.
// Collaborators: ConsoleNetworkCaptureAdapter owns selection, cancellation, and output budgets.
// Invariants: Endianness and interface numbering are section-local; raw timestamp ticks never pass through Number.
import { CONSOLE_NETWORK_CAPTURE_LIMITS } from "../../domain/consoleNetworkCapture.js";

type Resolution = { base: 2 | 10; exponent: number; offset_seconds: string };
type CaptureInterface = {
  id: string;
  linkType: number;
  snapLength: number;
  resolution: Resolution;
};
export interface CaptureRecord {
  ordinal: number;
  offset: number;
  dataOffset: number;
  originalLength: number;
  bytes: Buffer;
  interface: CaptureInterface;
  timestampTicks: string | null;
  timestampNs: string | null;
  limitations: string[];
}

export class CaptureContainerFailure extends Error {
  constructor(
    readonly offset: number,
    message: string,
    readonly resource = false,
  ) {
    super(message);
  }
}

const fail = (offset: number, message: string): never => {
  throw new CaptureContainerFailure(offset, message);
};
const align = (length: number): number => Math.ceil(length / 4) * 4;
const requireBytes = (
  bytes: Buffer,
  offset: number,
  length: number,
  end = bytes.length,
): void => {
  if (offset < 0 || length < 0 || offset + length > end)
    fail(offset, "Truncated capture record or block.");
};
const timestamp = (ticks: bigint, resolution: Resolution): string | null => {
  const denominator = BigInt(resolution.base) ** BigInt(resolution.exponent);
  const numerator = ticks * 1_000_000_000n;
  return numerator % denominator === 0n
    ? (
        numerator / denominator +
        BigInt(resolution.offset_seconds) * 1_000_000_000n
      ).toString()
    : null;
};
const recordLimits = (
  captured: number,
  original: number,
  iface: CaptureInterface,
  ns: string | null,
  ticks: string | null,
): string[] => [
  ...(captured < original
    ? [
        "Captured bytes are shorter than the producer-reported original packet length.",
      ]
    : []),
  ...(captured > original
    ? [
        "Producer-reported original packet length is smaller than its captured length; values are preserved.",
      ]
    : []),
  ...(iface.snapLength !== 0 && captured > iface.snapLength
    ? ["Captured length exceeds the interface snapshot length."]
    : []),
  ...(ns === null && ticks !== null
    ? [
        "Timestamp resolution is finer than integral nanoseconds; exact raw ticks and resolution are retained.",
      ]
    : []),
];

export interface CaptureContainer {
  format: "pcap" | "pcapng";
  records: Generator<CaptureRecord | null>;
  statistics: { unknownBlocks: number };
}

/** Container validation continues through unselected records and non-packet blocks. */
export const openCaptureContainer = (bytes: Buffer): CaptureContainer => {
  requireBytes(bytes, 0, 4);
  const magic = bytes.readUInt32BE(0);
  const statistics = { unknownBlocks: 0 };
  if (magic === 0x0a0d0d0a)
    return { format: "pcapng", records: pcapng(bytes, statistics), statistics };
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic))
    return { format: "pcap", records: pcap(bytes, magic), statistics };
  return fail(0, "Expected a supported pcap or pcapng magic number.");
};

function* pcap(bytes: Buffer, magic: number): Generator<CaptureRecord> {
  requireBytes(bytes, 0, 24);
  const little = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
  const u16 = (offset: number): number =>
    little ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
  const u32 = (offset: number): number =>
    little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  if (u16(4) !== 2 || u16(6) !== 4)
    fail(4, "Only classic pcap version 2.4 is supported.");
  const exponent = magic === 0xa1b23c4d || magic === 0x4d3cb2a1 ? 9 : 6;
  const iface: CaptureInterface = {
    id: "section:0/interface:0",
    linkType: u32(20) & 0xffff,
    snapLength: u32(16),
    resolution: { base: 10, exponent, offset_seconds: "0" },
  };
  let ordinal = 0;
  for (let offset = 24; offset < bytes.length;) {
    requireBytes(bytes, offset, 16);
    const captured = u32(offset + 8);
    const original = u32(offset + 12);
    requireBytes(bytes, offset + 16, captured);
    const fraction = u32(offset + 4);
    if (fraction >= 10 ** exponent)
      fail(
        offset + 4,
        "pcap timestamp fraction exceeds the declared resolution.",
      );
    const ticks =
      BigInt(u32(offset)) * 10n ** BigInt(exponent) + BigInt(fraction);
    const ns = timestamp(ticks, iface.resolution);
    yield {
      ordinal: ordinal++,
      offset,
      dataOffset: offset + 16,
      originalLength: original,
      bytes: bytes.subarray(offset + 16, offset + 16 + captured),
      interface: iface,
      timestampTicks: ticks.toString(),
      timestampNs: ns,
      limitations: recordLimits(
        captured,
        original,
        iface,
        ns,
        ticks.toString(),
      ),
    };
    offset += 16 + captured;
  }
}

function* pcapng(
  bytes: Buffer,
  statistics: CaptureContainer["statistics"],
): Generator<CaptureRecord | null> {
  let little = false;
  let section = -1;
  let sectionEnd: number | null = null;
  let interfaces: CaptureInterface[] = [];
  let ordinal = 0;
  const u16 = (offset: number): number =>
    little ? bytes.readUInt16LE(offset) : bytes.readUInt16BE(offset);
  const u32 = (offset: number): number =>
    little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const i64 = (offset: number): bigint =>
    little ? bytes.readBigInt64LE(offset) : bytes.readBigInt64BE(offset);
  const options = (
    start: number,
    end: number,
    visit?: (code: number, offset: number, length: number) => void,
  ): void => {
    for (let cursor = start; cursor < end;) {
      requireBytes(bytes, cursor, 4, end);
      const code = u16(cursor);
      const length = u16(cursor + 2);
      requireBytes(bytes, cursor + 4, align(length), end);
      if (code === 0) {
        if (length !== 0 || cursor + 4 !== end)
          fail(cursor, "Invalid pcapng end-of-options marker.");
        return;
      }
      visit?.(code, cursor + 4, length);
      cursor += 4 + align(length);
    }
  };
  for (let offset = 0; offset < bytes.length;) {
    requireBytes(bytes, offset, 12);
    const isSection = bytes.readUInt32BE(offset) === 0x0a0d0d0a;
    if (isSection) {
      if (sectionEnd !== null && offset !== sectionEnd)
        fail(
          offset,
          "Section boundary disagrees with the preceding declared section length.",
        );
      const bom = bytes.readUInt32BE(offset + 8);
      if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a)
        fail(offset + 8, "Invalid pcapng byte-order magic.");
      little = bom === 0x4d3c2b1a;
    } else if (section < 0)
      fail(offset, "A pcapng section header must precede other blocks.");
    const type = u32(offset);
    const length = u32(offset + 4);
    if (length < 12 || length % 4 !== 0)
      fail(offset + 4, "Invalid pcapng block length.");
    requireBytes(bytes, offset, length);
    if (u32(offset + length - 4) !== length)
      fail(offset + length - 4, "pcapng block length trailers disagree.");
    if (!isSection && sectionEnd !== null && offset + length > sectionEnd)
      fail(offset, "Block exceeds the declared pcapng section length.");
    const end = offset + length - 4;
    if (isSection) {
      if (length < 28) fail(offset, "Truncated pcapng section header.");
      if (u16(offset + 12) !== 1 || u16(offset + 14) !== 0)
        fail(offset + 12, "Only pcapng section version 1.0 is supported.");
      const declared = i64(offset + 16);
      if (declared < -1n || declared > BigInt(bytes.length - offset - length))
        fail(
          offset + 16,
          "Invalid or truncated pcapng declared section length.",
        );
      sectionEnd = declared === -1n ? null : offset + length + Number(declared);
      section++;
      interfaces = [];
      options(offset + 24, end);
      yield null;
    } else if (type === 1) {
      if (length < 20) fail(offset, "Truncated pcapng interface description.");
      if (
        interfaces.length >= CONSOLE_NETWORK_CAPTURE_LIMITS.interfacesPerSection
      )
        throw new CaptureContainerFailure(
          offset,
          "Interface table exceeds the bounded decoder's per-section memory capacity.",
          true,
        );
      const resolution: Resolution = {
        base: 10,
        exponent: 6,
        offset_seconds: "0",
      };
      const seen = new Set<number>();
      options(offset + 16, end, (code, position, size) => {
        if (code !== 9 && code !== 14) return;
        if (seen.has(code))
          fail(position, "Duplicate interface timestamp option is ambiguous.");
        seen.add(code);
        if (code === 9) {
          if (size !== 1) fail(position, "Invalid if_tsresol option length.");
          const value = bytes[position]!;
          resolution.base = (value & 0x80) === 0 ? 10 : 2;
          resolution.exponent = value & 0x7f;
        } else {
          if (size !== 8) fail(position, "Invalid if_tsoffset option length.");
          resolution.offset_seconds = i64(position).toString();
        }
      });
      interfaces.push({
        id: `section:${section}/interface:${interfaces.length}`,
        linkType: u16(offset + 8),
        snapLength: u32(offset + 12),
        resolution,
      });
      yield null;
    } else if (type === 6 || type === 2 || type === 3) {
      const simple = type === 3;
      if (length < (simple ? 16 : 32))
        fail(offset, "Truncated pcapng packet block.");
      const interfaceIndex = simple
        ? 0
        : type === 2
          ? u16(offset + 8)
          : u32(offset + 8);
      const iface =
        interfaces[interfaceIndex] ??
        fail(
          offset + 8,
          "Packet references an interface absent from its section.",
        );
      const original = u32(offset + (simple ? 8 : 24));
      const captured = simple
        ? Math.min(
            original,
            iface.snapLength === 0 ? original : iface.snapLength,
          )
        : u32(offset + 20);
      const dataOffset = offset + (simple ? 12 : 28);
      requireBytes(bytes, dataOffset, align(captured), end);
      if (simple && dataOffset + align(captured) !== end)
        fail(
          offset,
          "Simple packet block length disagrees with its interface snapshot length.",
        );
      if (!simple) options(dataOffset + align(captured), end);
      const ticks = simple
        ? null
        : (BigInt(u32(offset + 12)) << 32n) | BigInt(u32(offset + 16));
      const ns = ticks === null ? null : timestamp(ticks, iface.resolution);
      yield {
        ordinal: ordinal++,
        offset,
        dataOffset,
        originalLength: original,
        bytes: bytes.subarray(dataOffset, dataOffset + captured),
        interface: iface,
        timestampTicks: ticks?.toString() ?? null,
        timestampNs: ns,
        limitations: [
          ...recordLimits(
            captured,
            original,
            iface,
            ns,
            ticks?.toString() ?? null,
          ),
          ...(simple ? ["Simple packet blocks have no timestamp."] : []),
        ],
      };
    } else {
      statistics.unknownBlocks++;
      yield null;
    }
    offset += length;
  }
  if (sectionEnd !== null && sectionEnd !== bytes.length)
    fail(bytes.length, "Capture ended before its declared section boundary.");
}
