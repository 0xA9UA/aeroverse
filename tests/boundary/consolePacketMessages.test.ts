// MMA FILE SUMMARY
// Purpose: Verifies bounded HTTP/TCP interpretation through the real retained PCAP adapter.
// Responsibilities: Check framing, source bytes, gaps/conflicts, SYN/SYN-ACK generations and incomplete FIN boundaries.
// Invariants: Synthetic standards-shaped traffic is not proof of game/backend compatibility.
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { ConsoleNetworkCaptureAdapter } from "../../src/console/network/ConsoleNetworkCaptureAdapter.js";
import { consoleNetworkCaptureSchema } from "../../src/domain/consoleNetworkCapture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

type Segment = {
  sequence: number;
  payload?: Buffer;
  flags?: number;
  reverse?: boolean;
  acknowledgement?: number;
};
const request = Buffer.from(
  "POST /fixture/gts?pid=123 HTTP/1.1\r\nHost: fixture.invalid\r\nAuthorization: Bearer fixture-secret\r\nContent-Length: 6\r\n\r\nhello!",
);
const checksum = (bytes: Buffer): number => {
  let sum = 0;
  for (let index = 0; index < bytes.length; index += 2)
    sum += (bytes[index]! << 8) + (bytes[index + 1] ?? 0);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
};
const frame = (segment: Segment): Buffer => {
  const payload = segment.payload ?? Buffer.alloc(0),
    bytes = Buffer.alloc(54 + payload.length);
  bytes.writeUInt16BE(0x0800, 12);
  const ip = bytes.subarray(14, 34);
  ip[0] = 0x45;
  ip.writeUInt16BE(40 + payload.length, 2);
  ip[8] = 64;
  ip[9] = 6;
  ip.set([192, 0, 2, segment.reverse ? 20 : 10], 12);
  ip.set([192, 0, 2, segment.reverse ? 10 : 20], 16);
  ip.writeUInt16BE(checksum(ip), 10);
  const tcp = bytes.subarray(34);
  tcp.writeUInt16BE(segment.reverse ? 80 : 40000);
  tcp.writeUInt16BE(segment.reverse ? 40000 : 80, 2);
  tcp.writeUInt32BE(segment.sequence >>> 0, 4);
  tcp.writeUInt32BE(segment.acknowledgement ?? 0, 8);
  tcp[12] = 0x50;
  tcp[13] = segment.flags ?? 0x18;
  tcp.writeUInt16BE(65535, 14);
  payload.copy(tcp, 20);
  const pseudo = Buffer.alloc(12);
  ip.copy(pseudo, 0, 12, 20);
  pseudo[9] = 6;
  pseudo.writeUInt16BE(tcp.length, 10);
  tcp.writeUInt16BE(checksum(Buffer.concat([pseudo, tcp])), 16);
  return bytes;
};
const inspect = (segments: Segment[]) => inspectFrames(segments.map(frame));
const inspectFrames = async (
  frames: Buffer[],
  includePayload = false,
  originalLengths?: readonly number[],
) => {
  const root = await createTestTempDirectory("rea-http-pcap-");
  const pcapHeader = Buffer.alloc(24);
  pcapHeader.writeUInt32LE(0xa1b2c3d4);
  pcapHeader.writeUInt16LE(2, 4);
  pcapHeader.writeUInt16LE(4, 6);
  pcapHeader.writeUInt32LE(65535, 16);
  pcapHeader.writeUInt32LE(1, 20);
  const records = frames.map((bytes, index) => {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(1);
    header.writeUInt32LE(index, 4);
    header.writeUInt32LE(bytes.length, 8);
    header.writeUInt32LE(originalLengths?.[index] ?? bytes.length, 12);
    return Buffer.concat([header, bytes]);
  });
  const path = join(root, "http.pcap");
  await writeFile(path, Buffer.concat([pcapHeader, ...records]));
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: path,
    include_payload: includePayload,
  });
  if (!result.ok) throw result.error;
  return result.value;
};

it("returns a complete split HTTP request, redacted credential fields and exact source ranges after agreeing retransmission", async () => {
  const first = request.subarray(0, 73),
    second = request.subarray(73);
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 101, payload: first },
    { sequence: 101, payload: first },
    { sequence: 174, payload: second },
    { sequence: 101 + request.length, flags: 0x11 },
  ]);
  expect(report.coverage.reassembly).toBe("bounded-selected-tcp");
  expect(report.tcp_streams[0]).toMatchObject({
    status: "contiguous",
    agreeing_retransmitted_bytes: first.length,
    conflicting_overlap_bytes: 0,
    initial_boundary: "syn-observed",
    final_boundary_contiguous: true,
  });
  const message = report.messages[0];
  expect(message).toMatchObject({
    protocol: "http",
    status: "complete",
    bytes: request.length,
    wire_sha256: createHash("sha256").update(request).digest("hex"),
    http: {
      kind: "request",
      method: "POST",
      target: "/fixture/gts?pid=123",
      framing: "content-length",
      body: {
        bytes: 6,
        complete: true,
        sha256: createHash("sha256").update("hello!").digest("hex"),
      },
    },
  });
  if (message?.protocol !== "http")
    throw new Error("Expected HTTP interpretation");
  expect(
    message.http.headers.find(({ name }) => name === "Authorization"),
  ).toEqual({ name: "Authorization", value: null, redacted: true });
  expect(message.sources.map(({ bytes }) => bytes)).toEqual([
    first.length,
    second.length,
  ]);
  expect(message.sources.reduce((sum, source) => sum + source.bytes, 0)).toBe(
    message.bytes,
  );
  expect(report.packets.every(({ payload_hex }) => payload_hex === null)).toBe(
    true,
  );
  expect(JSON.stringify(report)).not.toContain("fixture-secret");
});

it("reorders captured segments by exact sequence including 32-bit wrap", async () => {
  const initial = 0xfffffff0,
    first = request.subarray(0, 37),
    second = request.subarray(37);
  const report = await inspect([
    { sequence: initial, flags: 2 },
    { sequence: initial + 1 + first.length, payload: second },
    { sequence: initial + 1, payload: first },
  ]);
  expect(report.messages[0]).toMatchObject({
    status: "complete",
    http: { method: "POST" },
  });
  expect(report.tcp_streams[0]?.first_sequence).toBe(initial + 1);
});

it("keeps missing body bytes incomplete and never joins HTTP across a sequence gap", async () => {
  const bodyStart = request.indexOf("\r\n\r\n") + 4;
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 101, payload: request.subarray(0, bodyStart + 2) },
    { sequence: 101 + bodyStart + 4, payload: request.subarray(bodyStart + 4) },
  ]);
  expect(report.tcp_streams[0]).toMatchObject({
    status: "gapped",
    missing_ranges: [{ bytes: 2 }],
  });
  expect(report.messages).toHaveLength(1);
  expect(report.messages[0]).toMatchObject({
    status: "incomplete",
    http: { body: { bytes: 2, complete: false } },
  });
});

it("reports disagreeing overlap bytes without selecting an HTTP interpretation", async () => {
  const altered = Buffer.from(request);
  altered[7] = altered[7]! ^ 1;
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 101, payload: request },
    { sequence: 101, payload: altered },
  ]);
  expect(report.tcp_streams[0]).toMatchObject({
    status: "conflicting",
    conflicting_overlap_bytes: 1,
  });
  expect(report.messages).toEqual([]);
});

it("uses distinct connection generations after a changed SYN sequence and labels midstream identity unknown", async () => {
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 101, payload: request },
    { sequence: 10000, flags: 2 },
    { sequence: 10001, payload: request },
  ]);
  expect(
    new Set(report.messages.map(({ connection_id }) => connection_id)).size,
  ).toBe(2);
  expect(report.tcp_streams.map(({ generation }) => generation)).toEqual([
    0, 1,
  ]);
  const midstream = await inspect([{ sequence: 101, payload: request }]);
  expect(midstream.tcp_streams[0]?.generation_basis).toBe("midstream-unknown");
});

it("requires a contiguous graceful FIN for close-delimited response completeness", async () => {
  const response = Buffer.from("HTTP/1.0 200 OK\r\n\r\nreply");
  const complete = await inspect([
    { sequence: 200, flags: 2, reverse: true },
    { sequence: 201, payload: response, reverse: true },
    { sequence: 201 + response.length, flags: 0x11, reverse: true },
  ]);
  expect(complete.messages[0]).toMatchObject({
    status: "complete",
    http: { framing: "close-delimited", body: { bytes: 5, complete: true } },
  });
  const missingTail = await inspect([
    { sequence: 200, flags: 2, reverse: true },
    { sequence: 201, payload: response, reverse: true },
    { sequence: 211 + response.length, flags: 0x11, reverse: true },
  ]);
  expect(missingTail.messages[0]).toMatchObject({
    status: "incomplete",
    http: { body: { complete: false } },
  });
  expect(missingTail.tcp_streams[0]?.missing_ranges.at(-1)?.bytes).toBe(10);
});

it("does not authenticate a FIN sequence from an uncaptured payload after a complete TCP header", async () => {
  const response = Buffer.from("HTTP/1.0 200 OK\r\n\r\nhello");
  const syn = frame({ sequence: 100, flags: 2, reverse: true });
  const data = frame({ sequence: 101, payload: response, reverse: true });
  const fin = frame({
    sequence: 101 + response.length,
    flags: 0x11,
    payload: Buffer.from("uncaptured-tail"),
    reverse: true,
  });
  const capturedFin = fin.subarray(0, 54);
  const report = await inspectFrames([syn, data, capturedFin], false, [
    syn.length,
    data.length,
    fin.length,
  ]);
  expect(report.packets.at(-1)).toMatchObject({
    payload_state: "partial",
    payload_bytes: 0,
    truncated: true,
    tcp: { flags: 0x11 },
  });
  expect(report.tcp_streams[0]).toMatchObject({
    status: "unsupported",
    final_boundary: "fin-observed",
    final_sequence: null,
    final_boundary_contiguous: false,
  });
  expect(report.messages).toEqual([]);
  const isolated = await inspectFrames([capturedFin], false, [fin.length]);
  expect(isolated.tcp_streams[0]).toMatchObject({
    status: "unsupported",
    final_sequence: null,
    final_boundary_contiguous: false,
  });
});

it("retains a first peer SYN-ACK and its same-sequence retransmission in one handshake", async () => {
  const response = Buffer.from(
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef",
  );
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 500, acknowledgement: 101, flags: 0x12, reverse: true },
    { sequence: 500, acknowledgement: 101, flags: 0x12, reverse: true },
    { sequence: 501, acknowledgement: 101, payload: response, reverse: true },
  ]);
  expect(
    new Set(report.tcp_streams.map(({ connection_id }) => connection_id)).size,
  ).toBe(1);
  expect(report.tcp_streams.map(({ generation }) => generation)).toEqual([
    0, 0,
  ]);
  expect(report.messages[0]).toMatchObject({
    status: "complete",
    http: { body: { bytes: 6, complete: true } },
  });
});

it("separates a changed SYN-ACK when the new connection's initial SYN was not captured", async () => {
  const prefix = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc");
  const report = await inspect([
    { sequence: 100, flags: 2 },
    { sequence: 500, acknowledgement: 101, flags: 0x12, reverse: true },
    { sequence: 501, payload: prefix, reverse: true },
    {
      sequence: 500 + prefix.length,
      acknowledgement: 901,
      flags: 0x12,
      reverse: true,
    },
    {
      sequence: 501 + prefix.length,
      payload: Buffer.from("def"),
      reverse: true,
    },
  ]);
  const server = report.tcp_streams.filter(
    ({ flow }) => flow.source.port === 80,
  );
  expect(server.map(({ generation }) => generation)).toEqual([0, 1]);
  expect(server[0]?.connection_id).not.toBe(server[1]?.connection_id);
  expect(report.messages).toHaveLength(1);
  expect(report.messages[0]).toMatchObject({
    status: "incomplete",
    http: { body: { bytes: 3, complete: false } },
  });
});

it("separates a SYN-ACK from same-direction midstream data without a recorded SYN", async () => {
  const prefix = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc");
  const report = await inspect([
    { sequence: 501, payload: prefix, reverse: true },
    {
      sequence: 500 + prefix.length,
      acknowledgement: 901,
      flags: 0x12,
      reverse: true,
    },
    {
      sequence: 501 + prefix.length,
      payload: Buffer.from("def"),
      reverse: true,
    },
  ]);
  expect(
    report.tcp_streams.map(({ generation_basis }) => generation_basis),
  ).toEqual(["midstream-unknown", "syn-observed"]);
  expect(report.tcp_streams.map(({ generation }) => generation)).toEqual([
    0, 1,
  ]);
  expect(report.messages[0]).toMatchObject({
    status: "incomplete",
    http: { body: { bytes: 3, complete: false } },
  });
});

it("retains transfer-coded messages as unsupported and rejects conflicting framing", async () => {
  const chunked = Buffer.from(
    "POST /fixture HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
  );
  expect(
    (await inspect([{ sequence: 1, payload: chunked }])).messages[0],
  ).toMatchObject({
    status: "unsupported",
    http: { framing: "unsupported", body: { complete: false } },
  });
  const ambiguous = Buffer.from(
    "POST /fixture HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
  );
  expect(
    (await inspect([{ sequence: 1, payload: ambiguous }])).messages[0]?.status,
  ).toBe("invalid");
});

it("interprets a complete UDP DNS question with exact source payload coordinates", async () => {
  const query = Buffer.concat([
    Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7]),
    Buffer.from("fixture"),
    Buffer.from([7]),
    Buffer.from("invalid"),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  const prefix = Buffer.from(frame({ sequence: 0 }).subarray(0, 34)),
    ip = prefix.subarray(14);
  ip[9] = 17;
  ip.writeUInt16BE(28 + query.length, 2);
  ip.writeUInt16BE(0, 10);
  ip.writeUInt16BE(checksum(ip), 10);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(40000);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(8 + query.length, 4);
  const report = await inspectFrames([Buffer.concat([prefix, udp, query])]);
  expect(report.messages[0]).toMatchObject({
    protocol: "dns",
    status: "complete",
    dns: {
      transaction_id: 0x1234,
      query: true,
      questions: [{ name: "fixture.invalid.", type: 1, class: 1 }],
    },
    sources: [
      {
        packet_id: report.packets[0]!.id,
        file_offset: report.packets[0]!.payload_offset,
        bytes: query.length,
        message_offset: 0,
      },
    ],
  });
  expect(report.messages[0]?.wire_sha256).toBe(
    report.packets[0]?.payload_sha256,
  );
});

it("rejects altered wire digests and byte ranges when released bytes can authenticate the imported message", async () => {
  const report = await inspectFrames(
    [frame({ sequence: 1, payload: request })],
    true,
  );
  const message = report.messages[0]!;
  expect(
    consoleNetworkCaptureSchema.safeParse({
      ...report,
      messages: [{ ...message, wire_sha256: "f".repeat(64) }],
    }).success,
  ).toBe(false);
  expect(
    consoleNetworkCaptureSchema.safeParse({
      ...report,
      messages: [
        { ...message, sources: [{ ...message.sources[0]!, file_offset: 0 }] },
      ],
    }).success,
  ).toBe(false);
});

it("requires unique message packet IDs to cover every packet contributing source bytes", async () => {
  const first = request.subarray(0, 73),
    second = request.subarray(73);
  const report = await inspect([
    { sequence: 101, payload: first },
    { sequence: 101 + first.length, payload: second },
  ]);
  const message = report.messages[0]!;
  expect(message.sources).toHaveLength(2);
  expect(message.packet_ids).toHaveLength(2);
  const [a, b] = message.packet_ids;
  expect(
    consoleNetworkCaptureSchema.safeParse({
      ...report,
      messages: [{ ...message, packet_ids: [a, a] }],
    }).success,
  ).toBe(false);
  expect(
    consoleNetworkCaptureSchema.safeParse({
      ...report,
      messages: [{ ...message, packet_ids: [b, a] }],
    }).success,
  ).toBe(true);
});
