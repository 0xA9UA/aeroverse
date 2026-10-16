// MMA FILE SUMMARY
// Purpose: Verifies console schemas, target-free MCP execution, target-content framing and Evidence linkage.
// Collaborators: Real packet decoder, supplied debugger port and shared server composition.
// Invariants: The debugger fixture tests contracts only; no hardware or game observation is claimed.
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import {
  ConsoleObservationService,
  type ConsoleObservationOperation,
} from "../../../src/application/ConsoleObservationService.js";
import { ConsoleNetworkCaptureAdapter } from "../../../src/console/network/ConsoleNetworkCaptureAdapter.js";
import { CONSOLE_OBSERVATION_TOOL_CONTRACTS } from "../../../src/contracts/consoleObservationToolContracts.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { observeConsoleDebuggerInputSchema } from "../../../src/domain/consoleDebugger.js";
import { consoleNetworkCaptureSchema } from "../../../src/domain/consoleNetworkCapture.js";
import { consoleCorrelationSchema } from "../../../src/domain/consoleObservation.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import {
  consoleCorrelationInput,
  writeConsoleCaptureFixture,
} from "../../fixtures/consoleObservation.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const consoleFixture = async () => {
  const root = await createTestTempDirectory("rea-console-mcp-");
  const path = await writeConsoleCaptureFixture(root);
  const session = createTestBinarySession(() => {
    throw new Error("Console tools must not acquire a binary provider");
  });
  const service = new ConsoleObservationService(
    new ConsoleNetworkCaptureAdapter(),
    {
      observe: (input) =>
        Promise.resolve(
          ok({
            observation_id: "fixture-partial",
            provider: input.provider,
            endpoint: input.endpoint,
            target: input.target,
            target_identity: "caller-declared-not-authenticated-by-stub",
            authority: "unverified-gdbstub",
            started_at: "2026-10-16T00:00:00Z",
            ended_at: "2026-10-16T00:00:01Z",
            completion: "partial",
            failure: "Fixture cleanup failure",
            negotiated_features: [],
            stops: [],
            cleanup: {
              status: "incomplete",
              remaining_breakpoints: ["0x02000000"],
              run_state: "unknown",
              reason: "Fixture socket closed",
            },
            limitations: [
              "Synthetic debugger application port; not a real debugger or game validation.",
            ],
          }),
        ),
    },
    (id) => session.evidenceById(id),
  );
  const server = createServer(
    { kind: "session", session },
    { consoleObservation: service },
  );
  const client = new Client({
    name: "console-observation-contract",
    version: "1",
  });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const advertised = (await client.listTools()).tools;
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  return { path, session, client, advertised, ajv };
};
type Fixture = Awaited<ReturnType<typeof consoleFixture>>;

const callConsole = async (
  fixture: Fixture,
  name: ConsoleObservationOperation,
  input: Record<string, unknown>,
) => {
  const response = await fixture.client.callTool({ name, arguments: input });
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  expect(toolContract(name).returnsTargetContent).toBe(true);
  expect(response._meta).toEqual({
    provenance: { untrusted_content: true, source: "analysis_target" },
  });
  const schema = fixture.advertised.find(
    (tool) => tool.name === name,
  )?.outputSchema;
  if (schema === undefined) throw new Error(`Missing output schema: ${name}`);
  const outputSchema: Record<string, unknown> = schema;
  expect(
    fixture.ajv.validate(outputSchema, response.structuredContent),
    JSON.stringify(fixture.ajv.errors),
  ).toBe(true);
  const evidence = parseEvidence(
    toolContract(name).outputSchema.parse(response.structuredContent),
  );
  expect(fixture.session.evidenceById(evidence.evidence_id)).toEqual(evidence);
  return evidence;
};
const captureEvidence = (fixture: Fixture) =>
  callConsole(fixture, "inspect_console_network_capture", {
    capture_path: fixture.path,
  });
const debuggerEvidence = (fixture: Fixture) =>
  callConsole(
    fixture,
    "observe_console_debugger",
    observeConsoleDebuggerInputSchema.parse(
      toolContract("observe_console_debugger").examples[0].input,
    ),
  );

it("exposes valid console schemas and retains offline, partial live and derived Evidence without a binary", async () => {
  const fixture = await consoleFixture();
  for (const contract of CONSOLE_OBSERVATION_TOOL_CONTRACTS) {
    const tool = fixture.advertised.find(({ name }) => name === contract.name);
    if (tool?.outputSchema === undefined)
      throw new Error(`Missing console contract: ${contract.name}`);
    const outputSchema: Record<string, unknown> = tool.outputSchema;
    expect(fixture.ajv.validateSchema(tool.inputSchema), contract.name).toBe(
      true,
    );
    expect(fixture.ajv.validateSchema(outputSchema), contract.name).toBe(true);
    expect(tool.annotations).toMatchObject(contract.annotations);
    for (const example of contract.examples)
      expect(
        fixture.ajv.validate(tool.inputSchema, example.input),
        JSON.stringify(fixture.ajv.errors),
      ).toBe(true);
  }
  const capture = await captureEvidence(fixture);
  const report = consoleNetworkCaptureSchema.parse(capture.normalized_result);
  expect(capture.subject?.digest.sha256).toBe(report.artifact.sha256);
  expect(capture.authority).toBe("historical-reference");
  expect(report.packets.map(({ ordinal }) => ordinal)).toEqual([0, 1]);
  expect(report.packets[0]?.payload_hex).toBeNull();
  const debuggerObservation = await debuggerEvidence(fixture);
  expect(debuggerObservation.subject).toBeNull();
  expect(debuggerObservation.authority).toBe("controlled-replay");
  expect(debuggerObservation.normalized_result).toMatchObject({
    completion: "partial",
    cleanup: {
      status: "incomplete",
      remaining_breakpoints: ["0x02000000"],
      run_state: "unknown",
    },
  });
  const correlation = await callConsole(
    fixture,
    "correlate_console_observations",
    consoleCorrelationInput(report.artifact.sha256, capture.evidence_id),
  );
  expect(correlation.evidence_links).toEqual([capture.evidence_id]);
  expect(correlation.confidence).toBe("derived");
  const graph = consoleCorrelationSchema.parse(correlation.normalized_result);
  expect(graph.backend_contract).toMatchObject({
    readiness: "requirements-only",
    fully_functional_replacement_verified: false,
  });
  expect(graph.edges.every(({ causal_proof }) => !causal_proof)).toBe(true);
  const invalid = await fixture.client.callTool({
    name: "inspect_console_network_capture",
    arguments: { capture_path: "relative.pcap" },
  });
  expect(invalid.isError).toBe(true);
  expect(invalid._meta).toEqual({
    provenance: { untrusted_content: true, source: "analysis_target" },
  });
});

it("links matching imported reports and preserves altered source claims as unlinked annotations", async () => {
  const fixture = await consoleFixture();
  const capture = await captureEvidence(fixture),
    debuggerObservation = await debuggerEvidence(fixture);
  const report = consoleNetworkCaptureSchema.parse(capture.normalized_result);
  const input = consoleCorrelationInput(report.artifact.sha256);
  const importedInput = {
    ...input,
    events: input.events.filter(({ kind }) => kind === "action"),
    network_captures: [
      { clock_id: "fixture", report, evidence_id: capture.evidence_id },
    ],
    debugger_observations: [
      {
        clock_id: "fixture",
        report: debuggerObservation.normalized_result,
        evidence_id: debuggerObservation.evidence_id,
      },
    ],
  };
  const imported = await callConsole(
    fixture,
    "correlate_console_observations",
    importedInput,
  );
  expect(imported.evidence_links).toEqual([
    capture.evidence_id,
    debuggerObservation.evidence_id,
  ]);
  expect(
    consoleCorrelationSchema.parse(imported.normalized_result).timeline,
  ).toHaveLength(3);
  expect(imported.limitations).toContain(
    "Imported debugger observation fixture-partial has partial completion; runtime coverage remains partial even if every supplied event is correlated.",
  );
  expect(imported.parameters).toMatchObject({
    debugger_observations: [{ cleanup: { status: "incomplete" } }],
  });
  const altered = await callConsole(fixture, "correlate_console_observations", {
    ...importedInput,
    debugger_observations: [],
    network_captures: [
      {
        clock_id: "fixture",
        evidence_id: capture.evidence_id,
        report: {
          ...report,
          limitations: [
            ...report.limitations,
            "Unrelated caller-added report claim",
          ],
        },
      },
    ],
  });
  expect(altered.evidence_links).toEqual([]);
  expect(altered.limitations).toContain(
    "Source Evidence annotations absent from this session or inconsistent with their reported source remain unlinked; retained matching sources alone are linked by this Evidence.",
  );
  const wrongSource = await callConsole(
    fixture,
    "correlate_console_observations",
    {
      ...input,
      events: input.events.map((event) => ({
        ...event,
        source: {
          ...event.source,
          artifact_sha256: "f".repeat(64),
          evidence_id: capture.evidence_id,
        },
      })),
    },
  );
  expect(wrongSource.evidence_links).toEqual([]);
});
