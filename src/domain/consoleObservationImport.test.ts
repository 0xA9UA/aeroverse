// MMA FILE SUMMARY
// Purpose: Verifies report normalization preserves identity, incomplete evidence and caller annotation boundaries.
// Collaborators: Canonical console schemas and report import helper; no runtime or network fixture.
import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { digestCanonicalValue } from "./canonicalDigest.js";
import { consoleDebuggerObservationSchema } from "./consoleDebugger.js";
import {
  consoleNetworkCaptureSchema,
  type ConsoleNetworkCapture,
} from "./consoleNetworkCapture.js";
import {
  CONSOLE_CORRELATION_LIMITS,
  correlateConsoleObservationsInputSchema,
  type ConsoleCorrelationInput,
} from "./consoleObservation.js";
import { normalizeConsoleObservationReports } from "./consoleObservationImport.js";
import { correlateConsoleObservations } from "./consoleCorrelation.js";

const sha = "a".repeat(64);
const payload = Buffer.from("packet");
const payloadSha = createHash("sha256").update(payload).digest("hex");
const packetReport = (): ConsoleNetworkCapture =>
  consoleNetworkCaptureSchema.parse({
    artifact: { path: "/retained/console.pcap", sha256: sha, bytes: 100 },
    format: "pcap",
    decoder: { id: "rea-native-pcap", version: "1" },
    packets: [
      {
        id: `sha256:${sha}/packet:0`,
        ordinal: 0,
        offset: 24,
        data_offset: 40,
        timestamp_ns: "1000000001",
        timestamp_ticks: "1000000001",
        timestamp_resolution: { base: 10, exponent: 9, offset_seconds: "0" },
        captured_length: 60,
        original_length: 60,
        interface_id: "section:0/interface:0",
        link_type: 1,
        snap_length: 65535,
        network: {
          version: 4,
          source: "192.0.2.1",
          destination: "192.0.2.2",
          protocol: 17,
        },
        flow: {
          transport: "udp",
          source: { address: "192.0.2.1", port: 1000 },
          destination: { address: "192.0.2.2", port: 2000 },
        },
        tcp: null,
        fragmentation: {
          state: "not_fragmented",
          offset_bytes: 0,
          more_fragments: false,
          identification: "1",
        },
        truncated: false,
        encryption: "unknown",
        payload_state: "available",
        payload_offset: 82,
        payload_bytes: payload.length,
        payload_sha256: payloadSha,
        payload_hex: null,
        limitations: ["packet limitation"],
      },
    ],
    coverage: {
      container: "complete",
      total_packets: 1,
      selected_packets: 1,
      unknown_blocks: 0,
      truncated_packets: 0,
      fragmented_packets: 0,
      unsupported_link_packets: 0,
      payload_release: "digest_only",
      reassembly: "not_attempted",
      decryption: "not_attempted",
    },
    limitations: ["capture limitation"],
  });
const debuggerReport = () =>
  consoleDebuggerObservationSchema.parse({
    observation_id: "retained-debugger-report",
    provider: "dolphin",
    endpoint: { transport: "tcp", host: "127.0.0.1", port: 55001 },
    target: {
      platform: "nintendo.nintendo_wii_family",
      processor: "powerpc",
      profile: "0.1.1",
      game_build_sha256: sha,
      runtime_version: "fixture",
    },
    target_identity: "caller-declared-not-authenticated-by-stub",
    authority: "emulator",
    started_at: "2026-10-16T01:02:03.000Z",
    ended_at: "2026-10-16T01:02:04.000Z",
    completion: "partial",
    failure: "fixture partial capture",
    negotiated_features: [],
    stops: [
      {
        stop_sequence: 7,
        observed_at: "2026-10-16T01:02:03.456Z",
        monotonic_ms: 123.25,
        reason: "stop-reply",
        signal: "05",
        pc: "0x80001234",
        hook: {
          label: "Send IPC request",
          kind: "ipc",
          address: "0x80001234",
          instruction_size: 4,
        },
        registers: [],
        memory: [
          {
            label: "arg",
            address: "0x80004000",
            requested_bytes: payload.length.toString(),
            bytes: payload.length,
            sha256: payloadSha,
            content_base64: payload.toString("base64"),
            truncated: false,
          },
        ],
        limitations: ["stop limitation"],
      },
    ],
    cleanup: {
      status: "incomplete",
      remaining_breakpoints: ["0x80001234"],
      run_state: "unknown",
      reason: "fixture disconnect",
    },
    limitations: ["debugger limitation"],
  });
const input = (
  overrides: Partial<ConsoleCorrelationInput> = {},
): ConsoleCorrelationInput =>
  correlateConsoleObservationsInputSchema.parse({
    target: {
      platform_id: "nintendo.nintendo_wii_family",
      profile_version: "0.1.1",
      game_build_id: "fixture build",
      game_sha256: sha,
    },
    session_id: "session",
    events: [],
    clocks: [],
    ...overrides,
  });

it("imports source-bound packet coordinates and complete payloads without inventing runtime binding", () => {
  const result = normalizeConsoleObservationReports(
    input({
      network_captures: [{ clock_id: "capture", report: packetReport() }],
    }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value[0]).toMatchObject({
    event_id: `sha256:${sha}/packet:0`,
    timestamp_ns: "1000000001",
    clock_id: "capture",
    kind: "network",
    source: { artifact_sha256: sha, locator: "packet:0@file-offset:24" },
    payload: {
      sha256: payloadSha,
      bytes: payload.length,
      complete: true,
      representation: "datagram",
    },
  });
  expect(result.value[0]?.limitations).toEqual(
    expect.arrayContaining([
      "capture limitation",
      "packet limitation",
      expect.stringContaining("caller-declared"),
    ]),
  );
  expect(result.value[0]?.parent).toBeUndefined();
});

it("excludes incomplete packet hashes from complete-payload matching", () => {
  const report = packetReport();
  report.packets[0]!.payload_state = "partial";
  const result = normalizeConsoleObservationReports(
    input({ network_captures: [{ clock_id: "capture", report }] }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value[0]?.payload).toBeUndefined();
  expect(result.value[0]?.flow).toBeDefined();
  expect(result.value[0]?.limitations).toContain(
    "Partial packet payload is excluded from complete-payload matching.",
  );
});

it("retains caller-classified IPC stop evidence and separate native buffers without causal edges", () => {
  const report = debuggerReport();
  const result = normalizeConsoleObservationReports(
    input({ debugger_observations: [{ clock_id: "host", report }] }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const timestamp = (
    BigInt(Date.parse(report.stops[0]!.observed_at)) * 1_000_000n
  ).toString();
  expect(result.value).toHaveLength(2);
  expect(result.value[0]).toMatchObject({
    kind: "ipc",
    timestamp_ns: timestamp,
    cpu: "powerpc",
    code: { address: "0x80001234", module_sha256: null, symbol: null },
    source: {
      artifact_sha256: digestCanonicalValue(report),
      locator: "/stops/0",
    },
  });
  expect(result.value[0]?.ipc).toBeUndefined();
  expect(result.value[0]?.limitations).toContain(
    "IPC classification is caller-supplied; request/channel semantics were not decoded.",
  );
  expect(result.value[0]?.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("completion is partial"),
      expect.stringContaining("cleanup is incomplete"),
    ]),
  );
  expect(result.value[1]).toMatchObject({
    kind: "native",
    payload: {
      complete: true,
      representation: "application-buffer",
      sha256: payloadSha,
    },
  });
  expect(result.value[1]?.parent).toBeUndefined();
});

it("keeps truncated buffer hashes incomplete and rejects inconsistent retained bytes", () => {
  const report = debuggerReport();
  const memory = report.stops[0]!.memory[0]!;
  memory.requested_bytes = "18446744073709551615";
  memory.truncated = true;
  const result = normalizeConsoleObservationReports(
    input({ debugger_observations: [{ clock_id: "host", report }] }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value[1]?.payload?.complete).toBe(false);
  memory.content_base64 = Buffer.from("different").toString("base64");
  expect(
    normalizeConsoleObservationReports(
      input({ debugger_observations: [{ clock_id: "host", report }] }),
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it.each(["platform", "profile", "game_build_sha256"] as const)(
  "rejects cross-target debugger %s bindings",
  (field) => {
    const report = debuggerReport();
    report.target[field] =
      field === "game_build_sha256" ? "b".repeat(64) : "different";
    expect(
      normalizeConsoleObservationReports(
        input({ debugger_observations: [{ clock_id: "host", report }] }),
      ),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
  },
);

it("does not round submillisecond or invalid observed_at timestamps", () => {
  const report = debuggerReport();
  report.stops[0]!.observed_at = "2026-10-16T01:02:03.456789Z";
  const result = normalizeConsoleObservationReports(
    input({ debugger_observations: [{ clock_id: "host", report }] }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value[0]?.timestamp_ns).toBeNull();
  expect(result.value[0]?.limitations).toContain(
    "The producer's observed_at is not an exact supported millisecond UTC timestamp; temporal correlation is unavailable.",
  );
});

it("bounds combined report expansion before importing packet/stop records", () => {
  const report = packetReport();
  report.packets = Array.from(
    { length: CONSOLE_CORRELATION_LIMITS.events + 1 },
    () => report.packets[0]!,
  );
  const request = input();
  request.network_captures = [{ clock_id: "capture", report }];
  expect(normalizeConsoleObservationReports(request)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError", resource: "memory" },
  });
});

it("rejects inconsistent packet payload and measured artifact bindings at the report contract", () => {
  const report = packetReport();
  report.packets[0]!.id = `sha256:${"b".repeat(64)}/packet:0`;
  expect(consoleNetworkCaptureSchema.safeParse(report).success).toBe(false);
  report.packets[0]!.id = `sha256:${sha}/packet:0`;
  report.coverage.payload_release = "hex";
  report.packets[0]!.payload_hex = Buffer.from("wrong").toString("hex");
  expect(consoleNetworkCaptureSchema.safeParse(report).success).toBe(false);
});

it("imports source-bound HTTP messages and separates observed requests from packets", () => {
  const report = packetReport();
  const packet = report.packets[0]!;
  const wire = Buffer.from(
    "GET /pokemondpds/worldexchange/info.asp HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
  );
  const wireSha = createHash("sha256").update(wire).digest("hex");
  report.artifact.bytes = 200;
  packet.flow!.transport = "tcp";
  packet.captured_length = 42 + wire.length;
  packet.original_length = packet.captured_length;
  packet.payload_bytes = wire.length;
  packet.payload_sha256 = wireSha;
  report.messages = [
    {
      id: "derived-http-0",
      protocol: "http",
      status: "complete",
      flow: packet.flow!,
      interface_id: packet.interface_id,
      connection_id: "fixture-connection",
      stream_id: "fixture-stream",
      stream_offset: 0,
      bytes: wire.length,
      wire_sha256: wireSha,
      packet_ids: [packet.id],
      sources: [
        {
          packet_id: packet.id,
          file_offset: packet.payload_offset!,
          bytes: wire.length,
          message_offset: 0,
        },
      ],
      limitations: [],
      http: {
        kind: "request",
        version: "HTTP/1.1",
        method: "GET",
        target: "/pokemondpds/worldexchange/info.asp",
        status_code: null,
        headers: [],
        framing: "no-body",
        body: {
          bytes: 0,
          sha256: createHash("sha256").digest("hex"),
          complete: true,
          representation: "transfer-payload",
        },
      },
    },
  ];
  report.message_coverage = {
    scope: "selected-packets",
    http_messages: 1,
    dns_messages: 0,
    unknown_tcp_directions: 0,
    unknown_udp_datagrams: 0,
  };
  const result = correlateConsoleObservations(
    input({
      network_captures: [{ clock_id: "capture", report }],
      client_addresses: [packet.flow!.source.address],
    }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const event = result.value.timeline.find(
    ({ event }) => event.event_id === "derived-http-0",
  )?.event;
  expect(event).toMatchObject({
    source: {
      artifact_sha256: digestCanonicalValue(report),
      locator: "/messages/0",
    },
    network_message: { protocol: "http", kind: "request" },
    timestamp_ns: packet.timestamp_ns,
    payload: { complete: true, representation: "decoded-message" },
  });
  expect(event?.parent).toBeUndefined();
  expect(result.value.backend_contract.services[0]).toMatchObject({
    outbound_event_ids: [packet.id, "derived-http-0"],
    outbound_message_event_ids: ["derived-http-0"],
    observed_http_requests: [
      {
        event_id: "derived-http-0",
        method: "GET",
        target: "/pokemondpds/worldexchange/info.asp",
        status: "complete",
      },
    ],
    protocol_semantics: "unknown",
  });
});
