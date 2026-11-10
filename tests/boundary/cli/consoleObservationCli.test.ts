// MMA FILE SUMMARY
// Purpose: Exercises all three console commands through built CLI processes and a simulated RSP socket.
// Invariants: Synthetic captures and debugger replies establish public transport integration, not real game compatibility.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { consoleNetworkCaptureSchema } from "../../../src/domain/consoleNetworkCapture.js";
import { consoleCorrelationSchema } from "../../../src/domain/consoleObservation.js";
import { consoleDebuggerObservationSchema } from "../../../src/domain/consoleDebugger.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { input, ppcFixture, stub } from "../../fixtures/consoleDebugger.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  consoleCorrelationInput,
  writeConsoleCaptureFixture,
} from "../../fixtures/consoleObservation.js";

cliTest(
  "runs capture, debugger observation and report correlation through the built JSON CLI",
  async ({ cli }) => {
    const runCliJson = async (arguments_: string[]) => {
      const result = await cli.run({ arguments: arguments_ });
      expect(result.exitCode, result.stdout + result.stderr).toBe(0);
      return result.json;
    };
    const root = await createTestTempDirectory("rea-console-cli-");
    const capturePath = await writeConsoleCaptureFixture(root);
    const inputPath = join(root, "capture-input.json");
    await writeFile(
      inputPath,
      JSON.stringify({
        capture_path: capturePath,
        packet_ordinals: [1, 0],
        include_payload: true,
      }),
    );
    const captureEvidence = parseEvidence(
      await runCliJson([
        "inspect-console-network-capture",
        "--input",
        inputPath,
        "--json",
      ]),
    );
    const capture = consoleNetworkCaptureSchema.parse(
      captureEvidence.normalized_result,
    );
    expect(captureEvidence.operation).toBe("inspect_console_network_capture");
    expect(captureEvidence.confidence).toBe("observed");
    expect(captureEvidence.subject?.digest.sha256).toBe(
      capture.artifact.sha256,
    );
    expect(capture.packets.map(({ ordinal }) => ordinal)).toEqual([1, 0]);
    expect(capture.packets.map(({ payload_hex }) => payload_hex)).toEqual([
      Buffer.from("pong").toString("hex"),
      Buffer.from("ping").toString("hex"),
    ]);
    expect(captureEvidence.subject?.local_path).toBe(capturePath);
    const remote = await stub(ppcFixture({ memory: "ping" }));
    const observationInput = input(remote.endpoint, {
      duration_ms: 5000,
      command_timeout_ms: 1000,
      max_stops: 2,
      breakpoint_scope: "exclusive-session",
      memory_policy: "bytes",
      hooks: [
        {
          label: "synthetic_send",
          kind: "network",
          address: "0x80001000",
          memory: [
            {
              label: "payload",
              address_register: "r3",
              length_register: "r4",
              length: 4,
            },
          ],
        },
      ],
    });
    const debuggerPath = join(root, "debugger-input.json");
    await writeFile(debuggerPath, JSON.stringify(observationInput));
    const debuggerEvidence = parseEvidence(
      await runCliJson([
        "observe-console-debugger",
        "--input",
        debuggerPath,
        "--json",
      ]),
    );
    const observation = consoleDebuggerObservationSchema.parse(
      debuggerEvidence.normalized_result,
    );
    expect(debuggerEvidence.operation).toBe("observe_console_debugger");
    expect(debuggerEvidence.parameters).toEqual(observationInput);
    expect(observation.endpoint).toEqual(remote.endpoint);
    expect(observation.target).toEqual(observationInput.target);
    expect(observation.completion).toBe("completed");
    expect(observation.stops[1]?.pc).toBe("0x80001000");
    expect(observation.stops[1]?.memory[0]).toMatchObject({
      bytes: 4,
      content_base64: Buffer.from("ping").toString("base64"),
      truncated: false,
    });
    expect(observation.cleanup).toMatchObject({
      status: "complete",
      remaining_breakpoints: [],
      run_state: "halted-observed",
    });
    expect(remote.peers[0]?.commands).toContain("Z0,80001000,4");
    expect(remote.peers[0]?.commands).toContain("z0,80001000,4");
    await expect.poll(() => remote.peers[0]?.socket.destroyed).toBe(true);
    const scenario = consoleCorrelationInput(capture.artifact.sha256);
    const correlationPath = join(root, "correlation-input.json");
    await writeFile(
      correlationPath,
      JSON.stringify({
        ...scenario,
        target: {
          ...scenario.target,
          platform_id: observation.target.platform,
        },
        events: scenario.events.filter(({ kind }) => kind === "action"),
        network_captures: [
          {
            clock_id: "fixture",
            report: capture,
            evidence_id: captureEvidence.evidence_id,
          },
        ],
        debugger_observations: [
          {
            clock_id: "debugger-host",
            report: observation,
            evidence_id: debuggerEvidence.evidence_id,
          },
        ],
      }),
    );
    const correlation = parseEvidence(
      await runCliJson([
        "correlate-console-observations",
        "--input",
        correlationPath,
        "--json",
      ]),
    );
    expect(correlation.operation).toBe("correlate_console_observations");
    expect(correlation.confidence).toBe("derived");
    expect(correlation.evidence_links).toEqual([]);
    expect(correlation.limitations).toContain(
      "Source Evidence annotations absent from this session or inconsistent with their reported source remain unlinked; retained matching sources alone are linked by this Evidence.",
    );
    const graph = consoleCorrelationSchema.parse(correlation.normalized_result);
    expect(graph.timeline).toHaveLength(6);
    expect(
      graph.edges.some(({ relationship }) => relationship === "same-payload"),
    ).toBe(true);
    expect(graph.edges.every(({ causal_proof }) => !causal_proof)).toBe(true);
    expect(graph.backend_contract).toMatchObject({
      readiness: "requirements-only",
      fully_functional_replacement_verified: false,
    });
  },
  60_000,
);
