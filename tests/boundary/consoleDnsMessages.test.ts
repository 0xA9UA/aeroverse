/** MMA FILE SUMMARY
 * Purpose: Checks RFC-shaped DNS wire decoding and malformed evidence boundaries without network activity.
 * Responsibilities: Compressed sections, exact RDATA hashes, partial records, presentation escapes and resource limits.
 * Invariants: Generated packets establish parser behavior, not reachable game services or historical backend responses.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decodeDnsDatagram } from "../../src/console/network/DnsMessages.js";

function name(value: string): Buffer {
  return Buffer.concat([
    ...value
      .split(".")
      .filter(Boolean)
      .map((label) =>
        Buffer.concat([
          Buffer.from([label.length]),
          Buffer.from(label, "ascii"),
        ]),
      ),
    Buffer.from([0]),
  ]);
}
function words(...values: number[]): Buffer {
  const data = Buffer.alloc(values.length * 2);
  values.forEach((value, index) => data.writeUInt16BE(value, index * 2));
  return data;
}
const pointer = (offset: number): Buffer => words(0xc000 | offset);
const question = (value: string): Buffer =>
  Buffer.concat([name(value), words(1, 1)]);
function header(flags: number, counts: readonly number[]): Buffer {
  return words(0x1234, flags, ...counts);
}
function record(
  owner: Buffer,
  type: number,
  data: Buffer,
  rrClass = 1,
): Buffer {
  const fields = Buffer.alloc(10);
  fields.writeUInt16BE(type);
  fields.writeUInt16BE(rrClass, 2);
  fields.writeUInt32BE(3600, 4);
  fields.writeUInt16BE(data.length, 8);
  return Buffer.concat([owner, fields, data]);
}
function decode(data: Buffer) {
  const result = decodeDnsDatagram(data);
  if (result === null) throw new Error("Expected DNS header.");
  return result;
}
describe("DNS wire metadata", () => {
  it("retains exact question case, terminal root, transaction ID and query direction", () => {
    const result = decode(
      Buffer.concat([
        header(0x0100, [1, 0, 0, 0]),
        question("gamestats2.gs.NintendoWiFi.net"),
      ]),
    );
    expect(result).toEqual({
      status: "complete",
      dns: {
        transaction_id: 0x1234,
        query: true,
        truncated_flag: false,
        rcode: 0,
        questions: [
          { name: "gamestats2.gs.NintendoWiFi.net.", type: 1, class: 1 },
        ],
        records: [],
      },
      limitations: [],
    });
  });
  it("decodes compressed CNAME/A, authority NS and additional AAAA/PTR while hashing unknown RDATA", () => {
    const q = question("gts2.nintendowifi.net");
    const alias = Buffer.concat([
      Buffer.from([7]),
      Buffer.from("backend"),
      pointer(17),
    ]);
    const aliasOffset = 12 + q.length + 12;
    const txt = Buffer.from([3, 0x61, 0x62, 0x63]);
    const result = decode(
      Buffer.concat([
        header(0x8180, [1, 2, 1, 3]),
        q,
        record(pointer(12), 5, alias),
        record(pointer(aliasOffset), 1, Buffer.from([203, 0, 113, 9])),
        record(pointer(17), 2, name("ns1.nintendowifi.net")),
        record(
          name("ns1.nintendowifi.net"),
          28,
          Buffer.from("20010db8000000000000000000000001", "hex"),
        ),
        record(name("9.113.0.203.in-addr.arpa"), 12, pointer(aliasOffset)),
        record(pointer(12), 16, txt),
      ]),
    );
    expect(result.status).toBe("complete");
    expect(result.dns.query).toBe(false);
    expect(
      result.dns.records.map((item) => [
        item.section,
        item.type,
        item.address,
        item.target,
      ]),
    ).toEqual([
      ["answer", 5, null, "backend.nintendowifi.net."],
      ["answer", 1, "203.0.113.9", null],
      ["authority", 2, null, "ns1.nintendowifi.net."],
      ["additional", 28, "2001:db8:0:0:0:0:0:1", null],
      ["additional", 12, null, "backend.nintendowifi.net."],
      ["additional", 16, null, null],
    ]);
    expect(result.dns.records[5]!.rdata_sha256).toBe(
      createHash("sha256").update(txt).digest("hex"),
    );
    expect(result.dns.records[0]!.rdata_sha256).toBe(
      createHash("sha256").update(alias).digest("hex"),
    );
    expect(result.dns.records[0]!.ttl).toBe(3600);
  });
  it("escapes arbitrary name bytes instead of interpreting dotted labels as hostnames", () => {
    const q = Buffer.concat([
      Buffer.from([3, 0x61, 0x2e, 0x5c, 0]),
      words(1, 1),
    ]);
    expect(
      decode(Buffer.concat([header(0, [1, 0, 0, 0]), q])).dns.questions[0]!
        .name,
    ).toBe("a\\046\\092.");
  });
  it("keeps sender-declared truncation distinct from successfully parsed retained fields and header RCODE", () => {
    const result = decode(
      Buffer.concat([header(0x8383, [1, 0, 0, 0]), question("gts.example")]),
    );
    expect(result.status).toBe("incomplete");
    expect(result.dns.truncated_flag).toBe(true);
    expect(result.dns.rcode).toBe(3);
    expect(result.dns.questions).toHaveLength(1);
    expect(result.limitations[0]).toContain("TC");
  });
  it("retains previous complete records on later wire truncation", () => {
    const q = question("a.example");
    const result = decode(
      Buffer.concat([
        header(0x8180, [1, 2, 0, 0]),
        q,
        record(pointer(12), 1, Buffer.from([192, 0, 2, 1])),
        pointer(12),
      ]),
    );
    expect(result.status).toBe("incomplete");
    expect(result.dns.records).toHaveLength(1);
    expect(result.dns.records[0]!.address).toBe("192.0.2.1");
  });
  it("labels EDNS extended RCODE as uninterpreted while retaining its option wire hash", () => {
    const result = decode(
      Buffer.concat([
        header(0x8180, [0, 0, 0, 1]),
        record(Buffer.from([0]), 41, Buffer.alloc(0), 1232),
      ]),
    );
    expect(result.status).toBe("complete");
    expect(result.dns.records[0]!.name).toBe(".");
    expect(
      result.limitations.some((item) => item.includes("extended RCODE")),
    ).toBe(true);
  });
});
describe("DNS malformed and resource boundaries", () => {
  it("does not classify fewer than twelve bytes as a DNS message", () => {
    expect(decodeDnsDatagram(Buffer.alloc(11))).toBeNull();
  });
  it.each([
    { bytes: Buffer.from([1, 0x78, 0xc0, 12]), reason: "cyclic" },
    { bytes: pointer(14), reason: "earlier name" },
    { bytes: pointer(16383), reason: "within the message" },
  ])("rejects invalid compression ($reason)", ({ bytes, reason }) => {
    const result = decode(
      Buffer.concat([header(0, [1, 0, 0, 0]), bytes, words(1, 1)]),
    );
    expect(result.status).toBe("invalid");
    expect(result.limitations.join(" ")).toContain(reason);
  });
  it("rejects expanded names beyond 255 wire octets", () => {
    const oversized = Buffer.concat([
      ...Array.from({ length: 4 }, () =>
        Buffer.concat([Buffer.from([63]), Buffer.alloc(63, 0x61)]),
      ),
      Buffer.from([0]),
    ]);
    expect(
      decode(Buffer.concat([header(0, [1, 0, 0, 0]), oversized, words(1, 1)]))
        .status,
    ).toBe("invalid");
  });
  it.each([
    { type: 1, data: Buffer.alloc(3), reason: "four octets" },
    { type: 28, data: Buffer.alloc(15), reason: "sixteen octets" },
    { type: 5, data: Buffer.from([0xc0]), reason: "RDLENGTH" },
    { type: 12, data: Buffer.from([0xc0, 12, 0]), reason: "RDLENGTH" },
  ])(
    "rejects malformed known RDATA ($type/$reason)",
    ({ type, data, reason }) => {
      const result = decode(
        Buffer.concat([
          header(0x8180, [1, 1, 0, 0]),
          question("a.example"),
          record(pointer(12), type, data),
        ]),
      );
      expect(result.status).toBe("invalid");
      expect(result.limitations.join(" ")).toContain(reason);
      expect(result.dns.records).toEqual([]);
    },
  );
  it("marks truncated names and question fields incomplete without reading outside the datagram", () => {
    expect(
      decode(Buffer.concat([header(0, [1, 0, 0, 0]), Buffer.from([0xc0])]))
        .status,
    ).toBe("incomplete");
    expect(
      decode(
        Buffer.concat([
          header(0, [1, 0, 0, 0]),
          name("a.example"),
          Buffer.from([0]),
        ]),
      ).status,
    ).toBe("incomplete");
  });
  it("refuses unsupported opcodes, label encodings and excessive declared section counts", () => {
    expect(decode(header(0x2800, [0, 0, 0, 0])).status).toBe("unsupported");
    expect(
      decode(Buffer.concat([header(0, [1, 0, 0, 0]), Buffer.from([0x40])]))
        .status,
    ).toBe("unsupported");
    expect(decode(header(0, [0, 65535, 0, 0])).status).toBe("unsupported");
  });
  it("bounds otherwise backward-valid compression chains independently of record count", () => {
    const q = Buffer.concat([Buffer.from([0]), words(1, 1)]);
    const records: Buffer[] = [];
    let previous = 12;
    let offset = 12 + q.length;
    for (let index = 0; index < 66; index++) {
      const rr = record(pointer(previous), 65280, Buffer.alloc(0));
      records.push(rr);
      previous = offset;
      offset += rr.length;
    }
    const result = decode(
      Buffer.concat([header(0x8180, [1, records.length, 0, 0]), q, ...records]),
    );
    expect(result.status).toBe("unsupported");
    expect(result.limitations.join(" ")).toContain("64-pointer");
    expect(result.dns.records).toHaveLength(64);
  });
  it("rejects reserved header bits and bytes outside declared section coverage", () => {
    expect(decode(header(0x0040, [0, 0, 0, 0])).status).toBe("invalid");
    const result = decode(
      Buffer.concat([
        header(0, [1, 0, 0, 0]),
        question("a.example"),
        Buffer.from([0]),
      ]),
    );
    expect(result.status).toBe("invalid");
    expect(result.dns.questions).toHaveLength(1);
  });
});
