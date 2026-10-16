// MMA FILE SUMMARY
// Purpose: Exercises built console capture and correlation commands with local JSON input files.
// Invariants: The real offline path requires no native provider, emulator, game or live endpoint.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { consoleNetworkCaptureSchema } from "../../../src/domain/consoleNetworkCapture.js";
import { consoleCorrelationSchema } from "../../../src/domain/consoleObservation.js";
import { runCliJson } from "../../fixtures/cliJsonProcess.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  consoleCorrelationInput,
  writeConsoleCaptureFixture,
} from "../../fixtures/consoleObservation.js";

it("preserves selected packet order and backend uncertainty through the built JSON CLI", async () => {
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
  expect(capture.packets.map(({ ordinal }) => ordinal)).toEqual([1, 0]);
  expect(capture.packets.map(({ payload_hex }) => payload_hex)).toEqual([
    Buffer.from("pong").toString("hex"),
    Buffer.from("ping").toString("hex"),
  ]);
  expect(captureEvidence.subject?.local_path).toBe(capturePath);
  const correlationPath = join(root, "correlation-input.json");
  await writeFile(
    correlationPath,
    JSON.stringify(
      consoleCorrelationInput(
        capture.artifact.sha256,
        captureEvidence.evidence_id,
      ),
    ),
  );
  const correlation = parseEvidence(
    await runCliJson([
      "correlate-console-observations",
      "--input",
      correlationPath,
      "--json",
    ]),
  );
  expect(correlation.evidence_links).toEqual([]);
  expect(correlation.limitations).toContain(
    "Source Evidence annotations absent from this session or inconsistent with their reported source remain unlinked; retained matching sources alone are linked by this Evidence.",
  );
  expect(
    consoleCorrelationSchema.parse(correlation.normalized_result)
      .backend_contract,
  ).toMatchObject({
    readiness: "requirements-only",
    fully_functional_replacement_verified: false,
  });
}, 60_000);
