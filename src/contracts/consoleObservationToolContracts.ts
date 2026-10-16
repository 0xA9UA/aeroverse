// MMA FILE SUMMARY
// Purpose: Defines the canonical CLI/MCP console observation contracts.
// Public interface: CONSOLE_OBSERVATION_TOOL_CONTRACTS.
// Collaborators: Domain schemas, canonical effects and Evidence output envelope.
// Invariants: Offline records, live debugger facts and inferred correlation have distinct authority.
import {
  inspectConsoleNetworkCaptureInputSchema,
  consoleNetworkCaptureSchema,
} from "../domain/consoleNetworkCapture.js";
import {
  observeConsoleDebuggerInputSchema,
  consoleDebuggerObservationSchema,
} from "../domain/consoleDebugger.js";
import {
  correlateConsoleObservationsInputSchema,
  consoleCorrelationSchema,
} from "../domain/consoleObservation.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

export const CONSOLE_OBSERVATION_TOOL_CONTRACTS = [
  {
    name: "inspect_console_network_capture",
    ...toolContractMetadata("inspect_console_network_capture"),
    description:
      "Inspect a retained local PCAP or PCAPNG file without contacting recorded endpoints. Returns measured source SHA-256, original packet coordinates, exact available timestamps, link/IP/TCP/UDP facts and payload digests. Bounded selected-packet TCP assembly exposes sequence gaps, agreeing retransmissions, conflicts and connection-generation uncertainty. Interprets plaintext HTTP/1.x requests/responses with supported framing and UDP DNS, with exact source byte ranges and body digests; credential header values are excluded from interpreted fields. Transfer-coded HTTP, TLS, IP-fragment reconstruction, application semantics and response pairing remain outside coverage. Packet selection preserves caller order after full container inspection; raw packet hex release is opt-in. No active binary target is required.",
    kind: "artifact-provider",
    inputSchema: inspectConsoleNetworkCaptureInputSchema,
    outputSchema: evidenceResultOf(consoleNetworkCaptureSchema),
    examples: [
      {
        title: "Inspect retained DS traffic with payload digests",
        input: {
          capture_path: "/captures/platinum-gts.pcapng",
          include_payload: false,
        },
      },
    ],
  },
  {
    name: "observe_console_debugger",
    ...toolContractMetadata("observe_console_debugger"),
    description:
      "Connect to a caller-selected console/emulator GDB Remote Serial Protocol endpoint for bounded stops, selected registers and hook memory. May interrupt and resume the target, install scoped address breakpoints and execute foreign code while collecting hooks. Requires an explicit final resume policy; hooks require exclusive breakpoint ownership. Returns observed stop order, host timing, selected bytes or digests, negotiated features and cleanup outcome, including partial results. Game image, processor and runtime identity are caller declarations; stub access does not authenticate hardware or a game build. No native binary admission is required.",
    kind: "runtime-provider",
    inputSchema: observeConsoleDebuggerInputSchema,
    outputSchema: evidenceResultOf(consoleDebuggerObservationSchema),
    examples: [
      {
        title: "Observe the selected melonDS ARM9 debugger endpoint",
        input: {
          provider: "gdb-remote",
          endpoint: { transport: "tcp", host: "127.0.0.1", port: 3333 },
          target: {
            platform: "nintendo.nintendo_ds_family",
            profile: "0.1.1",
            processor: "arm9",
            game_build_sha256: "a".repeat(64),
            runtime_version: "caller-selected-melonDS-build",
          },
          register_map: [
            { name: "r0", number: 0, bits: 32, byte_order: "little" },
            { name: "pc", number: 15, bits: 32, byte_order: "little" },
          ],
          duration_ms: 1000,
          max_stops: 1,
          resume_on_finish: false,
        },
      },
    ],
  },
  {
    name: "correlate_console_observations",
    ...toolContractMetadata("correlate_console_observations"),
    description:
      "Correlate supplied console actions, native code, IPC and network events, including reports from the console capture/debugger tools, into a source-linked timeline with explicit clock offsets and uncertainty. Distinguishes reported parent links, analyst hypotheses, matching payloads and temporal candidates; every edge states that causal proof is absent. Unknown or incompatible clocks, build/session mismatches and bounded incomplete coverage remain explicit. Returns source-linked endpoint requirements and action scenarios for backend reconstruction, with protocol semantics and replacement readiness unverified. Input facts and artifact digests remain caller supplied; no active target or network access is required.",
    kind: "application",
    inputSchema: correlateConsoleObservationsInputSchema,
    outputSchema: evidenceResultOf(consoleCorrelationSchema),
    examples: [
      {
        title: "Record a retained GTS scenario packet",
        input: {
          target: {
            platform_id: "nintendo.nintendo_ds_family",
            profile_version: "0.1.1",
            game_build_id: "Pokemon Platinum; select exact region/revision",
            game_sha256: "a".repeat(64),
          },
          session_id: "platinum-gts-1",
          clocks: [
            {
              clock_id: "capture",
              offset_ns: "0",
              uncertainty_ns: "1000000",
              evidence:
                "Explicit caller-selected clock relation; replace with measured calibration.",
            },
          ],
          events: [
            {
              event_id: "packet-0",
              session_id: "platinum-gts-1",
              game_sha256: "a".repeat(64),
              kind: "network",
              label: "Captured GTS scenario packet",
              clock_id: "capture",
              timestamp_ns: "1000000000",
              source: { artifact_sha256: "b".repeat(64), locator: "packet:0" },
              flow: {
                transport: "udp",
                source: { address: "192.0.2.10", port: 40000 },
                destination: { address: "192.0.2.20", port: 12345 },
              },
            },
          ],
          client_addresses: ["192.0.2.10"],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
