// MMA FILE SUMMARY
// Purpose: Supplies tiny retained packet bytes and declared scenario facts for public console workflows.
// Public interface: writeConsoleCaptureFixture() and consoleCorrelationInput().
// Invariants: Synthetic traffic and scenario facts establish transport behavior, not game compatibility.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Two complete Ethernet/IPv4/UDP packets, with a valid IP checksum and UDP checksum omitted. */
export const writeConsoleCaptureFixture = async (
  root: string,
): Promise<string> => {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(1, 20);
  const records = ["ping", "pong"].map((text, index) => {
    const payload = Buffer.from(text);
    const frame = Buffer.alloc(14 + 20 + 8 + payload.length);
    frame.writeUInt16BE(0x0800, 12);
    const ip = frame.subarray(14, 34);
    ip[0] = 0x45;
    ip.writeUInt16BE(20 + 8 + payload.length, 2);
    ip[8] = 64;
    ip[9] = 17;
    ip.set([192, 0, 2, index === 0 ? 10 : 20], 12);
    ip.set([192, 0, 2, index === 0 ? 20 : 10], 16);
    let sum = 0;
    for (let offset = 0; offset < 20; offset += 2)
      sum += ip.readUInt16BE(offset);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    ip.writeUInt16BE(~sum & 0xffff, 10);
    frame.writeUInt16BE(index === 0 ? 40000 : 12345, 34);
    frame.writeUInt16BE(index === 0 ? 12345 : 40000, 36);
    frame.writeUInt16BE(8 + payload.length, 38);
    payload.copy(frame, 42);
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1, 0);
    record.writeUInt32LE(500 + index * 1000, 4);
    record.writeUInt32LE(frame.length, 8);
    record.writeUInt32LE(frame.length, 12);
    return Buffer.concat([record, frame]);
  });
  const path = join(root, "console.pcap");
  await writeFile(path, Buffer.concat([header, ...records]));
  return path;
};

/** One action and packet share an explicitly declared synthetic clock. */
export const consoleCorrelationInput = (
  artifactSha256: string,
  evidenceId?: string,
) => ({
  target: {
    platform_id: "nintendo.nintendo_ds_family",
    profile_version: "0.1.1",
    game_build_id: "synthetic transport fixture",
    game_sha256: "a".repeat(64),
  },
  session_id: "fixture-session",
  clocks: [
    {
      clock_id: "fixture",
      offset_ns: "0",
      uncertainty_ns: "0",
      evidence:
        "Synthetic fixture clock; no real emulator/game synchronization claim.",
    },
  ],
  events: [
    {
      event_id: "action",
      session_id: "fixture-session",
      game_sha256: "a".repeat(64),
      kind: "action",
      label: "Synthetic network menu action",
      clock_id: "fixture",
      timestamp_ns: "1000000000",
      source: { artifact_sha256: artifactSha256, locator: "fixture:action" },
    },
    {
      event_id: "packet",
      session_id: "fixture-session",
      game_sha256: "a".repeat(64),
      kind: "network",
      label: "Retained synthetic UDP packet",
      clock_id: "fixture",
      timestamp_ns: "1000500000",
      source: {
        artifact_sha256: artifactSha256,
        locator: "packet:0",
        ...(evidenceId === undefined ? {} : { evidence_id: evidenceId }),
      },
      flow: {
        transport: "udp",
        source: { address: "192.0.2.10", port: 40000 },
        destination: { address: "192.0.2.20", port: 12345 },
      },
    },
  ],
  client_addresses: ["192.0.2.10"],
});
