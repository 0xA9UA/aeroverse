// MMA FILE SUMMARY
// Purpose: Decodes retained link/IP/TCP/UDP headers without reconstructing conversations.
// Public interface: dissectPacket() returns packet facts and an optional bounded payload view.
// Collaborators: CaptureContainers supplies record coordinates; adapter hashes/releases the view.
// Invariants: No DNS, replay, checksum validation, stream reassembly, or implicit decryption.
import type { ConsoleNetworkPacket } from "../../domain/consoleNetworkCapture.js";
import type { CaptureRecord } from "./CaptureContainers.js";

type Facts = Pick<
  ConsoleNetworkPacket,
  | "network"
  | "flow"
  | "tcp"
  | "fragmentation"
  | "encryption"
  | "payload_state"
  | "limitations"
>;
export interface PacketDissection extends Facts {
  payload: Buffer | null;
  payloadOffset: number | null;
  supportedLink: boolean;
}

/** Protocol incompleteness is evidence attached to a packet, not a failed file decode. */
export const dissectPacket = (record: CaptureRecord): PacketDissection => {
  const result: PacketDissection = {
    network: null,
    flow: null,
    tcp: null,
    fragmentation: {
      state: "unknown",
      offset_bytes: null,
      more_fragments: null,
      identification: null,
    },
    encryption: "unknown",
    payload_state: "unavailable",
    payload: null,
    payloadOffset: null,
    supportedLink: true,
    limitations: [...record.limitations],
  };
  const link = decodeLink(record, result);
  if (link === null) return result;
  const ip = decodeIp(record, result, link);
  if (ip !== null) decodeTransport(record, result, ip);
  return result;
};

type IpBoundary = {
  end: number;
  cursor: number;
  protocol: number;
  partial: boolean;
};
const decodeLink = (
  record: CaptureRecord,
  result: PacketDissection,
): { start: number; etherType: number } | null => {
  const bytes = record.bytes;
  let start = 0;
  let etherType: number;
  switch (record.interface.linkType) {
    case 1: {
      if (bytes.length < 14) {
        result.limitations.push("Ethernet header is incomplete.");
        return null;
      }
      start = 14;
      etherType = bytes.readUInt16BE(12);
      while ([0x8100, 0x88a8, 0x9100].includes(etherType)) {
        if (bytes.length < start + 4) {
          result.limitations.push("Ethernet VLAN header is incomplete.");
          return null;
        }
        etherType = bytes.readUInt16BE(start + 2);
        start += 4;
      }
      break;
    }
    case 101:
      etherType =
        bytes.length === 0
          ? 0
          : bytes[0]! >>> 4 === 4
            ? 0x0800
            : bytes[0]! >>> 4 === 6
              ? 0x86dd
              : 0;
      break;
    case 228:
      etherType = 0x0800;
      break;
    case 229:
      etherType = 0x86dd;
      break;
    case 113:
      if (bytes.length < 16) {
        result.limitations.push("Linux cooked-v1 header is incomplete.");
        return null;
      }
      etherType = bytes.readUInt16BE(14);
      start = 16;
      break;
    case 276:
      if (bytes.length < 20) {
        result.limitations.push("Linux cooked-v2 header is incomplete.");
        return null;
      }
      etherType = bytes.readUInt16BE(0);
      start = 20;
      break;
    default:
      result.supportedLink = false;
      result.limitations.push(
        `Link type ${record.interface.linkType} is preserved but not decoded.`,
      );
      return null;
  }
  if (etherType !== 0x0800 && etherType !== 0x86dd) {
    result.limitations.push(
      "This link-layer protocol is not decoded as IPv4 or IPv6.",
    );
    return null;
  }
  return { start, etherType };
};

const decodeIp = (
  record: CaptureRecord,
  result: PacketDissection,
  link: { start: number; etherType: number },
): IpBoundary | null => {
  const bytes = record.bytes;
  const { start, etherType } = link;
  const version = etherType === 0x0800 ? 4 : 6;
  if (
    bytes.length < start + (version === 4 ? 20 : 40) ||
    bytes[start]! >>> 4 !== version
  ) {
    result.limitations.push(
      "IP header is incomplete or disagrees with its link-layer protocol.",
    );
    return null;
  }
  let end: number;
  let cursor: number;
  let protocol: number;
  let partial = bytes.length < record.originalLength;
  if (version === 4) {
    const headerLength = (bytes[start]! & 15) * 4;
    const totalLength = bytes.readUInt16BE(start + 2);
    if (
      headerLength < 20 ||
      totalLength < headerLength ||
      bytes.length < start + headerLength
    ) {
      result.limitations.push(
        "IPv4 header or declared packet length is invalid/incomplete.",
      );
      return null;
    }
    protocol = bytes[start + 9]!;
    result.network = {
      version,
      source: ipv4(bytes, start + 12),
      destination: ipv4(bytes, start + 16),
      protocol,
    };
    const fragment = bytes.readUInt16BE(start + 6);
    const offset = (fragment & 0x1fff) * 8;
    const more = (fragment & 0x2000) !== 0;
    result.fragmentation = {
      state: offset !== 0 || more ? "fragmented" : "not_fragmented",
      offset_bytes: offset,
      more_fragments: more,
      identification: bytes.readUInt16BE(start + 4).toString(),
    };
    end = Math.min(bytes.length, start + totalLength);
    cursor = start + headerLength;
    if (bytes.length < start + totalLength) {
      partial = true;
      result.limitations.push(
        "Retained bytes do not cover the IPv4 total length.",
      );
    }
  } else {
    protocol = bytes[start + 6]!;
    result.network = {
      version,
      source: ipv6(bytes, start + 8),
      destination: ipv6(bytes, start + 24),
      protocol,
    };
    result.fragmentation = {
      state: "not_fragmented",
      offset_bytes: 0,
      more_fragments: false,
      identification: null,
    };
    const payloadLength = bytes.readUInt16BE(start + 4);
    if (payloadLength === 0) {
      result.limitations.push(
        "Zero-length IPv6 payloads and jumbo-payload options are not decoded.",
      );
      return null;
    }
    end = Math.min(bytes.length, start + 40 + payloadLength);
    cursor = start + 40;
    if (bytes.length < start + 40 + payloadLength) {
      partial = true;
      result.limitations.push(
        "Retained bytes do not cover the IPv6 payload length.",
      );
    }
    let fragmentSeen = false;
    while ([0, 43, 60, 51, 44].includes(protocol)) {
      if (cursor + 2 > end) {
        result.limitations.push("IPv6 extension header is incomplete.");
        return null;
      }
      const next = bytes[cursor]!;
      const length =
        protocol === 44
          ? 8
          : protocol === 51
            ? (bytes[cursor + 1]! + 2) * 4
            : (bytes[cursor + 1]! + 1) * 8;
      if (cursor + length > end) {
        result.limitations.push(
          "IPv6 extension header exceeds retained packet bytes.",
        );
        return null;
      }
      if (protocol === 44) {
        if (fragmentSeen) {
          result.limitations.push(
            "Multiple IPv6 fragment headers are not decoded.",
          );
          return null;
        }
        fragmentSeen = true;
        const fragment = bytes.readUInt16BE(cursor + 2);
        const offset = fragment & 0xfff8;
        const more = (fragment & 1) !== 0;
        result.fragmentation = {
          state: offset !== 0 || more ? "fragmented" : "not_fragmented",
          offset_bytes: offset,
          more_fragments: more,
          identification: bytes.readUInt32BE(cursor + 4).toString(),
        };
      }
      cursor += length;
      protocol = next;
      result.network.protocol = protocol;
      // Non-initial fragments contain continuation bytes, not another extension/transport header.
      if ((result.fragmentation.offset_bytes ?? 0) !== 0) break;
    }
  }
  return { end, cursor, protocol, partial };
};

const decodeTransport = (
  record: CaptureRecord,
  result: PacketDissection,
  ip: IpBoundary,
): void => {
  const bytes = record.bytes;
  const network = result.network;
  if (network === null) return;
  let { end, cursor, protocol, partial } = ip;
  network.protocol = protocol;
  if (result.fragmentation.state === "fragmented") {
    partial = true;
    result.limitations.push(
      "IP fragments are retained individually; datagram reassembly is not attempted.",
    );
    if ((result.fragmentation.offset_bytes ?? 0) !== 0) return;
  }
  if (protocol === 50) {
    result.encryption = "encrypted";
    result.limitations.push(
      "IP ESP conceals transport headers/payload; decryption is not attempted.",
    );
    return;
  }
  if (protocol !== 6 && protocol !== 17) {
    result.limitations.push(
      `IP protocol ${protocol} is not decoded as TCP/UDP.`,
    );
    return;
  }
  const minimum = protocol === 6 ? 20 : 8;
  if (cursor + minimum > end) {
    result.limitations.push(
      "Transport header is incomplete; endpoints and payload are unavailable.",
    );
    return;
  }
  result.flow = {
    transport: protocol === 6 ? "tcp" : "udp",
    source: {
      address: network.source,
      port: bytes.readUInt16BE(cursor),
    },
    destination: {
      address: network.destination,
      port: bytes.readUInt16BE(cursor + 2),
    },
  };
  let payloadStart: number;
  if (protocol === 6) {
    const headerLength = (bytes[cursor + 12]! >>> 4) * 4;
    result.tcp = {
      sequence: bytes.readUInt32BE(cursor + 4),
      acknowledgement: bytes.readUInt32BE(cursor + 8),
      flags: ((bytes[cursor + 12]! & 1) << 8) | bytes[cursor + 13]!,
    };
    if (headerLength < 20 || cursor + headerLength > end) {
      result.limitations.push(
        "TCP data offset is invalid or extends beyond retained bytes.",
      );
      return;
    }
    payloadStart = cursor + headerLength;
  } else {
    const length = bytes.readUInt16BE(cursor + 4);
    if (length < 8) {
      result.limitations.push(
        "UDP length is invalid or requires unsupported IPv6 jumbo-payload handling.",
      );
      return;
    }
    if (cursor + length > end) {
      partial = true;
      result.limitations.push(
        "Retained packet bytes do not cover the UDP datagram length.",
      );
    }
    end = Math.min(end, cursor + length);
    payloadStart = cursor + 8;
  }
  result.payload = bytes.subarray(payloadStart, end);
  result.payloadOffset = record.dataOffset + payloadStart;
  result.payload_state = partial ? "partial" : "available";
  return;
};

const ipv4 = (bytes: Buffer, offset: number): string =>
  Array.from(bytes.subarray(offset, offset + 4)).join(".");
const ipv6 = (bytes: Buffer, offset: number): string =>
  Array.from({ length: 8 }, (_, index) =>
    bytes.readUInt16BE(offset + index * 2).toString(16),
  ).join(":");
