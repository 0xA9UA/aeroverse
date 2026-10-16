/** MMA FILE SUMMARY
 * Purpose: Derives bounded DNS metadata from complete caller-selected UDP datagrams.
 * Responsibilities: Header/section decoding, compressed names, known address/target RDATA and exact wire hashes.
 * Public interface: decodeDnsDatagram(); packet identity and capture provenance remain caller-owned.
 * Sources: RFC 1035 sections 3.3, 3.4 and 4.1; RFC 3596 section 2.2 for AAAA.
 * Invariants: No network access, resolution, guessed secrets, decompression beyond DNS names or unknown-RDATA interpretation.
 */
import { createHash } from "node:crypto";
import {
  CONSOLE_MESSAGE_LIMITS,
  type ConsoleDnsMessage,
} from "../../domain/consoleNetworkMessages.js";

type Status = ConsoleDnsMessage["status"];
export type DecodedDnsDatagram = {
  status: Status;
  dns: ConsoleDnsMessage["dns"];
  limitations: string[];
};
class DnsFailure extends Error {
  constructor(
    readonly status: Exclude<Status, "complete">,
    message: string,
  ) {
    super(message);
  }
}
const fail = (status: Exclude<Status, "complete">, message: string): never => {
  throw new DnsFailure(status, message);
};
function requireBytes(offset: number, bytes: number, limit: number): void {
  if (offset + bytes > limit)
    fail(
      "incomplete",
      "DNS wire data ends before the declared field is complete.",
    );
}
/** Presentation escapes preserve arbitrary label bytes and literal dots; names retain source case and terminal root. */
function displayLabel(bytes: Buffer): string {
  return [...bytes]
    .map((byte) =>
      byte > 32 && byte < 127 && byte !== 46 && byte !== 92
        ? String.fromCharCode(byte)
        : `\\${byte.toString().padStart(3, "0")}`,
    )
    .join("");
}
function readName(
  data: Buffer,
  start: number,
  encodedLimit = data.length,
): { name: string; next: number } {
  let cursor = start;
  let next: number | undefined;
  let expandedBytes = 1;
  let pointers = 0;
  const labels: string[] = [];
  const visited = new Set<number>();
  for (;;) {
    if (visited.has(cursor))
      fail("invalid", "DNS compression contains a cyclic name reference.");
    visited.add(cursor);
    const limit = next === undefined ? encodedLimit : data.length;
    requireBytes(cursor, 1, limit);
    const length = data[cursor]!;
    if (length === 0)
      return {
        name: labels.length === 0 ? "." : `${labels.join(".")}.`,
        next: next ?? cursor + 1,
      };
    if ((length & 0xc0) === 0xc0) {
      requireBytes(cursor, 2, limit);
      const pointer = ((length & 0x3f) << 8) | data[cursor + 1]!;
      if (pointer < 12 || pointer >= data.length || pointer >= cursor)
        fail(
          "invalid",
          "DNS compression pointer does not reference an earlier name within the message.",
        );
      if (++pointers > 64)
        fail(
          "unsupported",
          "DNS name exceeds the bounded 64-pointer expansion budget.",
        );
      next ??= cursor + 2;
      cursor = pointer;
      continue;
    }
    if ((length & 0xc0) !== 0)
      fail(
        "unsupported",
        "DNS uses an unsupported extended or reserved label encoding.",
      );
    requireBytes(cursor + 1, length, limit);
    expandedBytes += length + 1;
    if (expandedBytes > 255)
      fail("invalid", "Expanded DNS name exceeds its 255-octet format limit.");
    labels.push(displayLabel(data.subarray(cursor + 1, cursor + 1 + length)));
    cursor += length + 1;
  }
}
function rdataTarget(data: Buffer, start: number, end: number): string {
  try {
    const target = readName(data, start, end);
    if (target.next !== end)
      fail(
        "invalid",
        "DNS name RDATA does not consume exactly its declared RDLENGTH.",
      );
    return target.name;
  } catch (error) {
    if (error instanceof DnsFailure && error.status === "incomplete")
      fail("invalid", "DNS name RDATA exceeds its declared RDLENGTH.");
    throw error;
  }
}
/** Unknown RR types retain their RDATA wire hash; compression bytes are hashed as captured, not synthesized names. */
class DnsDecoder {
  offset = 12;
  readonly limitations = new Set<string>();
  constructor(
    readonly data: Buffer,
    readonly dns: ConsoleDnsMessage["dns"],
  ) {}
  question(): void {
    const name = readName(this.data, this.offset);
    this.offset = name.next;
    requireBytes(this.offset, 4, this.data.length);
    this.dns.questions.push({
      name: name.name,
      type: this.data.readUInt16BE(this.offset),
      class: this.data.readUInt16BE(this.offset + 2),
    });
    this.offset += 4;
  }
  record(
    section: ConsoleDnsMessage["dns"]["records"][number]["section"],
  ): void {
    const name = readName(this.data, this.offset);
    this.offset = name.next;
    requireBytes(this.offset, 10, this.data.length);
    const type = this.data.readUInt16BE(this.offset);
    const rrClass = this.data.readUInt16BE(this.offset + 2);
    const ttl = this.data.readUInt32BE(this.offset + 4);
    const length = this.data.readUInt16BE(this.offset + 8);
    this.offset += 10;
    requireBytes(this.offset, length, this.data.length);
    const end = this.offset + length;
    const rdata = this.data.subarray(this.offset, end);
    let address: string | null = null;
    let target: string | null = null;
    if (rrClass === 1 && type === 1) {
      if (length !== 4)
        fail(
          "invalid",
          "Internet-class A RDATA must contain exactly four octets.",
        );
      address = [...rdata].join(".");
    } else if (rrClass === 1 && type === 28) {
      if (length !== 16)
        fail(
          "invalid",
          "Internet-class AAAA RDATA must contain exactly sixteen octets.",
        );
      address = Array.from({ length: 8 }, (_, index) =>
        rdata.readUInt16BE(index * 2).toString(16),
      ).join(":");
    } else if (type === 2 || type === 5 || type === 12)
      target = rdataTarget(this.data, this.offset, end);
    else
      this.limitations.add(
        "Uninterpreted RDATA is retained by its exact wire SHA256; its application semantics are unknown.",
      );
    if (type === 41)
      this.limitations.add(
        "rcode contains only the DNS header's low four bits; EDNS extended RCODE and options are not interpreted.",
      );
    this.dns.records.push({
      section,
      name: name.name,
      type,
      class: rrClass,
      ttl,
      rdata_sha256: createHash("sha256").update(rdata).digest("hex"),
      address,
      target,
    });
    this.offset = end;
  }
}
/** Caller supplies complete UDP/53 payloads; null only means the candidate is too short to carry a DNS header. */
export function decodeDnsDatagram(payload: Buffer): DecodedDnsDatagram | null {
  if (payload.length < 12) return null;
  const flags = payload.readUInt16BE(2);
  const dns: ConsoleDnsMessage["dns"] = {
    transaction_id: payload.readUInt16BE(0),
    query: (flags & 0x8000) === 0,
    truncated_flag: (flags & 0x0200) !== 0,
    rcode: flags & 15,
    questions: [],
    records: [],
  };
  const decoder = new DnsDecoder(payload, dns);
  let status: Status = dns.truncated_flag ? "incomplete" : "complete";
  if (dns.truncated_flag)
    decoder.limitations.add(
      "DNS sender set TC; this message does not establish a complete answer even if all retained fields parse.",
    );
  try {
    if (payload.length > 65535)
      fail(
        "unsupported",
        "DNS datagram exceeds the bounded 65535-byte parser budget.",
      );
    if ((flags & 0x0040) !== 0)
      fail("invalid", "DNS header sets the reserved Z bit.");
    if (((flags >>> 11) & 15) !== 0)
      fail(
        "unsupported",
        "Only standard DNS QUERY opcode sections are interpreted.",
      );
    const counts = [4, 6, 8, 10].map((offset) => payload.readUInt16BE(offset));
    if (
      counts.reduce((sum, count) => sum + count, 0) >
      CONSOLE_MESSAGE_LIMITS.dnsRecords
    )
      fail(
        "unsupported",
        "Declared DNS section counts exceed the bounded record budget.",
      );
    for (let index = 0; index < counts[0]!; index++) decoder.question();
    const sections = ["answer", "authority", "additional"] as const;
    for (let section = 0; section < sections.length; section++)
      for (let index = 0; index < counts[section + 1]!; index++)
        decoder.record(sections[section]!);
    if (decoder.offset !== payload.length)
      fail(
        "invalid",
        "DNS datagram contains trailing bytes outside its declared sections.",
      );
  } catch (error) {
    if (!(error instanceof DnsFailure)) throw error;
    status = error.status;
    decoder.limitations.add(error.message);
  }
  return { status, dns, limitations: [...decoder.limitations] };
}
