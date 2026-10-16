// MMA FILE SUMMARY
// Purpose: Exercises real offline capture bytes at the stable filesystem/decoder boundary.
// Responsibilities: Prove record identity, exact timestamps, bounded selection and protocol uncertainty.
// Collaborators: Workspace-owned temporary directories; native console capture adapter.
// Invariants: Synthetic fixtures perform no network or console execution.
import { createHash } from "node:crypto";
import { open, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { ConsoleNetworkCaptureAdapter } from "../../src/console/network/ConsoleNetworkCaptureAdapter.js";
import {
  CONSOLE_NETWORK_CAPTURE_LIMITS,
  consoleNetworkCaptureSchema,
} from "../../src/domain/consoleNetworkCapture.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";

const digest = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const captureFile = async (bytes: Buffer): Promise<string> => {
  const root = await createTestTempDirectory("rea-console-capture-");
  const path = join(root, "capture.bin");
  await writeFile(path, bytes);
  return path;
};
const pcap = (
  frames: Buffer[],
  {
    little = true,
    nano = false,
    link = 1,
    seconds = 17,
    fraction = 123,
    originals = frames.map((frame) => frame.length),
  } = {},
): Buffer => {
  const header = Buffer.alloc(24);
  const write16 = (buffer: Buffer, value: number, offset: number): void => {
    if (little) buffer.writeUInt16LE(value, offset);
    else buffer.writeUInt16BE(value, offset);
  };
  const write32 = (buffer: Buffer, value: number, offset: number): void => {
    if (little) buffer.writeUInt32LE(value, offset);
    else buffer.writeUInt32BE(value, offset);
  };
  write32(header, nano ? 0xa1b23c4d : 0xa1b2c3d4, 0);
  write16(header, 2, 4);
  write16(header, 4, 6);
  write32(header, 65_535, 16);
  write32(header, link, 20);
  return Buffer.concat([
    header,
    ...frames.map((frame, index) => {
      const record = Buffer.alloc(16);
      write32(record, seconds, 0);
      write32(record, fraction, 4);
      write32(record, frame.length, 8);
      write32(record, originals[index]!, 12);
      return Buffer.concat([record, frame]);
    }),
  ]);
};
const ethernet = (ip: Buffer, type = 0x0800, vlan = false): Buffer => {
  const header = Buffer.alloc(vlan ? 18 : 14);
  header.writeUInt16BE(vlan ? 0x8100 : type, 12);
  if (vlan) header.writeUInt16BE(type, 16);
  return Buffer.concat([header, ip]);
};
const udp = (payload = Buffer.from("game-token=sample")): Buffer => {
  const header = Buffer.alloc(8);
  header.writeUInt16BE(12345, 0);
  header.writeUInt16BE(29900, 2);
  header.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([header, payload]);
};
const ipv4 = (body: Buffer, protocol = 17, fragment = 0): Buffer => {
  const header = Buffer.alloc(20);
  header[0] = 0x45;
  header.writeUInt16BE(20 + body.length, 2);
  header.writeUInt16BE(123, 4);
  header.writeUInt16BE(fragment, 6);
  header[9] = protocol;
  Buffer.from([192, 0, 2, 1, 198, 51, 100, 2]).copy(header, 12);
  return Buffer.concat([header, body]);
};
const ipv6 = (body: Buffer, protocol = 17): Buffer => {
  const header = Buffer.alloc(40);
  header[0] = 0x60;
  header.writeUInt16BE(body.length, 4);
  header[6] = protocol;
  header.writeUInt16BE(0x2001, 8);
  header.writeUInt16BE(0xdb8, 10);
  header[23] = 1;
  header.writeUInt16BE(0x2001, 24);
  header.writeUInt16BE(0xdb8, 26);
  header[39] = 2;
  return Buffer.concat([header, body]);
};

const block = (type: number, body: Buffer, little = true): Buffer => {
  const result = Buffer.alloc(12 + Math.ceil(body.length / 4) * 4);
  if (little) {
    result.writeUInt32LE(type, 0);
    result.writeUInt32LE(result.length, 4);
    result.writeUInt32LE(result.length, result.length - 4);
  } else {
    result.writeUInt32BE(type, 0);
    result.writeUInt32BE(result.length, 4);
    result.writeUInt32BE(result.length, result.length - 4);
  }
  body.copy(result, 8);
  return result;
};
const section = (little = true): Buffer => {
  const body = Buffer.alloc(16);
  if (little) {
    body.writeUInt32LE(0x1a2b3c4d, 0);
    body.writeUInt16LE(1, 4);
    body.writeBigInt64LE(-1n, 8);
  } else {
    body.writeUInt32BE(0x1a2b3c4d, 0);
    body.writeUInt16BE(1, 4);
    body.writeBigInt64BE(-1n, 8);
  }
  return block(0x0a0d0d0a, body, little);
};
const iface = (
  link = 1,
  little = true,
  resolution = 6,
  offset = 0n,
  snapLength = 65_535,
): Buffer => {
  const body = Buffer.alloc(32);
  const write16 = (value: number, position: number): void => {
    if (little) body.writeUInt16LE(value, position);
    else body.writeUInt16BE(value, position);
  };
  write16(link, 0);
  if (little) body.writeUInt32LE(snapLength, 4);
  else body.writeUInt32BE(snapLength, 4);
  write16(9, 8);
  write16(1, 10);
  body[12] = resolution;
  write16(14, 16);
  write16(8, 18);
  if (little) body.writeBigInt64LE(offset, 20);
  else body.writeBigInt64BE(offset, 20);
  return block(1, body, little);
};
const enhanced = (
  frame: Buffer,
  { little = true, ticks = 17_000_123n, interfaceIndex = 0 } = {},
): Buffer => {
  const body = Buffer.alloc(20 + Math.ceil(frame.length / 4) * 4);
  const write = (value: number, position: number): void => {
    if (little) body.writeUInt32LE(value, position);
    else body.writeUInt32BE(value, position);
  };
  write(interfaceIndex, 0);
  write(Number(ticks >> 32n), 4);
  write(Number(ticks & 0xffff_ffffn), 8);
  write(frame.length, 12);
  write(frame.length, 16);
  frame.copy(body, 20);
  return block(6, body, little);
};

it("binds VLAN/IPv4/UDP payload coordinates to the measured pcap without releasing bytes by default", async () => {
  const payload = Buffer.from("game-token=sample");
  const frame = ethernet(ipv4(udp(payload)), 0x0800, true);
  const bytes = pcap([frame]);
  const path = await captureFile(bytes);
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: path,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(consoleNetworkCaptureSchema.safeParse(result.value).success).toBe(
    true,
  );
  expect(result.value.artifact).toEqual({
    path,
    sha256: digest(bytes),
    bytes: bytes.length,
  });
  expect(result.value.packets[0]).toMatchObject({
    id: `sha256:${digest(bytes)}/packet:0`,
    ordinal: 0,
    offset: 24,
    data_offset: 40,
    timestamp_ns: "17000123000",
    timestamp_ticks: "17000123",
    captured_length: frame.length,
    original_length: frame.length,
    interface_id: "section:0/interface:0",
    flow: {
      transport: "udp",
      source: { address: "192.0.2.1", port: 12345 },
      destination: { address: "198.51.100.2", port: 29900 },
    },
    payload_offset: 86,
    payload_bytes: payload.length,
    payload_sha256: digest(payload),
    payload_hex: null,
    payload_state: "available",
  });
  expect(JSON.stringify(result.value)).not.toContain(payload.toString());
  expect(await readFile(path)).toEqual(bytes);
});

it.each([true, false])(
  "preserves nanosecond pcap times beyond Number precision (little endian: %s)",
  async (little) => {
    const path = await captureFile(
      pcap([ipv4(udp())], {
        little,
        nano: true,
        link: 101,
        seconds: 0xffff_ffff,
        fraction: 999_999_999,
      }),
    );
    const result = await new ConsoleNetworkCaptureAdapter().inspect({
      capture_path: path,
      include_payload: true,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.packets[0]?.timestamp_ns).toBe("4294967295999999999");
    expect(result.value.packets[0]?.payload_hex).toBe(
      Buffer.from("game-token=sample").toString("hex"),
    );
  },
);

it("selects zero-based ordinals in caller order while validating every record", async () => {
  const bytes = pcap([
    ethernet(ipv4(udp(Buffer.from("one")))),
    ethernet(ipv4(udp(Buffer.from("two")))),
  ]);
  const path = await captureFile(bytes);
  const adapter = new ConsoleNetworkCaptureAdapter();
  const result = await adapter.inspect({
    capture_path: path,
    packet_ordinals: [1, 0],
    include_payload: true,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.packets.map((packet) => packet.ordinal)).toEqual([1, 0]);
  expect(result.value.packets.map((packet) => packet.payload_hex)).toEqual([
    "74776f",
    "6f6e65",
  ]);
  const malformed = await captureFile(Buffer.concat([bytes, Buffer.alloc(3)]));
  const rejected = await adapter.inspect({
    capture_path: malformed,
    packet_ordinals: [0],
  });
  expect(rejected).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  expect(
    await adapter.inspect({ capture_path: path, packet_ordinals: [2] }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  expect(
    await adapter.inspect({ capture_path: path, packet_ordinals: [0, 0] }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it("distinguishes captured TCP segments from missing bytes and reassembled messages", async () => {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(4000, 0);
  header.writeUInt16BE(443, 2);
  header.writeUInt32BE(0xffff_ffff, 4);
  header[12] = 0x50;
  header[13] = 0x18;
  const frame = ethernet(
    ipv4(Buffer.concat([header, Buffer.from([1, 2, 3, 4])]), 6),
  );
  const path = await captureFile(
    pcap([frame.subarray(0, -2)], { originals: [frame.length] }),
  );
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: path,
    include_payload: true,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.packets[0]).toMatchObject({
    truncated: true,
    tcp: { sequence: 0xffff_ffff, acknowledgement: 0, flags: 24 },
    payload_state: "partial",
    payload_hex: "0102",
    encryption: "unknown",
  });
  expect(result.value.coverage).toMatchObject({
    truncated_packets: 1,
    reassembly: "bounded-selected-tcp",
    decryption: "not_attempted",
  });
});

it("does not parse continuation fragments as transport headers", async () => {
  const first = ethernet(ipv4(udp(Buffer.from("first-fragment")), 17, 0x2000));
  const continuation = ethernet(ipv4(Buffer.from("continuation"), 17, 3));
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: await captureFile(pcap([first, continuation])),
    include_payload: true,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.coverage.fragmented_packets).toBe(2);
  expect(result.value.packets[0]).toMatchObject({
    payload_state: "partial",
    fragmentation: { state: "fragmented", more_fragments: true },
  });
  expect(result.value.packets[1]).toMatchObject({
    flow: null,
    payload_sha256: null,
    payload_hex: null,
    fragmentation: { offset_bytes: 24 },
  });
});

it("walks IPv6 extensions but marks ESP and unknown links without invented payloads", async () => {
  const extension = Buffer.alloc(8);
  extension[0] = 17;
  const ipv6Frame = ethernet(
    ipv6(Buffer.concat([extension, udp(Buffer.from("v6"))]), 0),
    0x86dd,
  );
  const esp = ethernet(ipv6(Buffer.alloc(12), 50), 0x86dd);
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: await captureFile(pcap([ipv6Frame, esp])),
    include_payload: true,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.packets[0]).toMatchObject({
    network: { version: 6, source: "2001:db8:0:0:0:0:0:1", protocol: 17 },
    flow: { transport: "udp" },
    payload_hex: "7636",
  });
  expect(result.value.packets[1]).toMatchObject({
    encryption: "encrypted",
    flow: null,
    payload_state: "unavailable",
  });
  const unknown = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: await captureFile(pcap([ipv6Frame], { link: 999 })),
  });
  expect(unknown.ok).toBe(true);
  if (!unknown.ok) return;
  expect(unknown.value.packets[0]).toMatchObject({
    network: null,
    flow: null,
    payload_hex: null,
  });
  expect(unknown.value.coverage.unsupported_link_packets).toBe(1);
});

it("resets pcapng interface IDs/endian clocks per section and retains uint64 timestamps exactly", async () => {
  const frame = ethernet(ipv4(udp(Buffer.from("multi"))));
  const ticks = 0xffff_ffff_ffff_ffffn;
  const bytes = Buffer.concat([
    section(),
    iface(999),
    iface(1, true, 0x89, -2n),
    enhanced(frame, { ticks: 512n, interfaceIndex: 1 }),
    section(false),
    iface(1, false, 9),
    enhanced(frame, { little: false, ticks }),
  ]);
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: await captureFile(bytes),
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.packets[0]).toMatchObject({
    interface_id: "section:0/interface:1",
    timestamp_ticks: "512",
    timestamp_ns: "-1000000000",
    timestamp_resolution: { base: 2, exponent: 9, offset_seconds: "-2" },
  });
  expect(result.value.packets[1]).toMatchObject({
    interface_id: "section:1/interface:0",
    timestamp_ticks: ticks.toString(),
    timestamp_ns: ticks.toString(),
    link_type: 1,
  });
});

it("retains subnanosecond clocks losslessly and represents missing SPB timestamps explicitly", async () => {
  const frame = ethernet(ipv4(udp(Buffer.alloc(0))));
  const simpleBody = Buffer.alloc(4 + Math.ceil(frame.length / 4) * 4);
  simpleBody.writeUInt32LE(frame.length, 0);
  frame.copy(simpleBody, 4);
  const bytes = Buffer.concat([
    section(),
    iface(1, true, 10),
    enhanced(frame, { ticks: 1n }),
    block(3, simpleBody),
    block(0x12345678, Buffer.alloc(0)),
  ]);
  const result = await new ConsoleNetworkCaptureAdapter().inspect({
    capture_path: await captureFile(bytes),
    include_payload: true,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.packets[0]).toMatchObject({
    timestamp_ns: null,
    timestamp_ticks: "1",
    timestamp_resolution: { base: 10, exponent: 10 },
    payload_bytes: 0,
    payload_hex: "",
    payload_sha256: digest(Buffer.alloc(0)),
  });
  expect(result.value.packets[1]).toMatchObject({
    timestamp_ns: null,
    timestamp_ticks: null,
    timestamp_resolution: null,
  });
  expect(result.value.coverage).toMatchObject({
    total_packets: 2,
    unknown_blocks: 1,
  });
});

it("rejects pcapng block trailer mismatches and references to interfaces in a prior section", async () => {
  const frame = ethernet(ipv4(udp()));
  const trailer = Buffer.concat([section(), iface(), enhanced(frame)]);
  trailer.writeUInt32LE(12, trailer.length - 4);
  const adapter = new ConsoleNetworkCaptureAdapter();
  expect(
    await adapter.inspect({ capture_path: await captureFile(trailer) }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  const crossSection = Buffer.concat([
    section(),
    iface(),
    section(),
    enhanced(frame),
  ]);
  expect(
    await adapter.inspect({ capture_path: await captureFile(crossSection) }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it("returns typed cancellation, path and resource failures without partial successful reports", async () => {
  const adapter = new ConsoleNetworkCaptureAdapter();
  const controller = new AbortController();
  controller.abort();
  expect(
    await adapter.inspect(
      { capture_path: "/absent" },
      { signal: controller.signal },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
  expect(
    await adapter.inspect({ capture_path: "relative.pcap" }),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  const path = await captureFile(pcap([]));
  const link = `${path}.link`;
  await symlink(path, link);
  expect(await adapter.inspect({ capture_path: link })).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  const file = await open(path, "r+");
  try {
    await file.truncate(CONSOLE_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  } finally {
    await file.close();
  }
  expect(await adapter.inspect({ capture_path: path })).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError", resource: "file-size" },
  });
});
