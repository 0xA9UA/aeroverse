import { basename, join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it, vi } from "vitest";
import {
  verifyNoTokenOwnedProcesses,
  type ProcessOwnershipHost,
  type ProcessRunTokenReadDiagnostic,
} from "./ProcessOwnership.js";
import { ProcessOwnershipEvidenceOwner } from "./ProcessOwnershipEvidence.js";

const helper = vi.hoisted(() => ({ diagnostic: undefined as unknown }));
vi.mock("./ExecFileOutput.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./ExecFileOutput.js")>();
  return {
    ...original,
    execFileOutput: async (command: string, arguments_: readonly string[]) => {
      let stdout = "";
      if (basename(command) === "fixture-swiftc") {
        const output = arguments_[arguments_.indexOf("-o") + 1];
        if (output === undefined) throw new Error("Missing helper output");
        await (await import("node:fs/promises")).writeFile(output, "fixture");
      } else {
        stdout = JSON.stringify({
          results: [
            {
              pid: 900,
              state: "unavailable",
              reason: "malformed_procargs",
              diagnostic: helper.diagnostic,
            },
          ],
        });
      }
      return { stdout, stderr: "", stdoutBytes: stdout.length, stderrBytes: 0 };
    },
  };
});

import { createDarwinProcessRunTokenReader } from "./DarwinProcessRunTokenReader.js";

const row = {
  pid: 900,
  parentPid: 1,
  processGroupId: 900,
  state: "S",
  command: "fixture",
};
const diagnostic: ProcessRunTokenReadDiagnostic = {
  stage: "argc",
  buffer_bytes: 4,
  argument_count: -1,
  offset: 4,
  pointer_size: -1,
  code_signing_flags: 0x04000800,
};
const createReader = () =>
  createDarwinProcessRunTokenReader({
    compiler: {
      kind: "swiftc",
      executable: join(tmpdir(), "fixture-swiftc"),
      sdkRoot: tmpdir(),
    },
    environment: {},
  });

it("retains native numeric diagnostics through a failing ownership sweep without changing classification", async () => {
  helper.diagnostic = diagnostic;
  const reader = createReader();
  const signalGroup = vi.fn();
  try {
    const tokens = await reader.read([row]);
    expect(tokens.get(row.pid)).toEqual({
      state: "unavailable",
      reason: "malformed_procargs",
      diagnostic,
    });
    const host: ProcessOwnershipHost = {
      platform: "darwin",
      listProcesses: async () => [row],
      environment: async () => ({}),
      runTokens: async () => tokens,
      processIdentities: async () =>
        new Map([
          [
            row.pid,
            {
              state: "readable",
              identity: "start:900",
              effectiveUid: process.getuid?.() ?? 0,
              lifecycle: { state: "observed", lifecycle: "non-zombie" },
              relation: {
                state: "observed",
                parentPid: 1,
                processGroupId: 900,
              },
            },
          ],
        ]),
      signalGroup,
    };
    expect(
      await verifyNoTokenOwnedProcesses("run-token", host, [], {
        leaderPid: 100,
        processGroupId: 100,
        evidenceOwner: new ProcessOwnershipEvidenceOwner(),
      }),
    ).toEqual({
      cleaned: false,
      reason:
        "process ownership token could not be read for 1 live process(es): malformed_procargs=1; live candidates 900=malformed_procargs",
      failures: [
        {
          pid: 900,
          reason: "environment-unreadable",
          diagnostic: "malformed_procargs",
          tokenReadDiagnostic: diagnostic,
        },
      ],
    });
    expect(signalGroup).not.toHaveBeenCalled();
  } finally {
    await reader.close();
  }
});

it("preserves unavailable header and code-signing facts as unknown", async () => {
  const partialDiagnostic = {
    stage: "header",
    buffer_bytes: 3,
    offset: 0,
    pointer_size: 8,
  };
  helper.diagnostic = partialDiagnostic;
  const reader = createReader();
  try {
    expect((await reader.read([row])).get(row.pid)).toEqual({
      state: "unavailable",
      reason: "malformed_procargs",
      diagnostic: {
        ...partialDiagnostic,
        argument_count: null,
        code_signing_flags: null,
      },
    });
  } finally {
    await reader.close();
  }
});

it.each([
  { ...diagnostic, stage: "private-argument" },
  { ...diagnostic, environment: "PRIVATE_VALUE=private-environment" },
  { ...diagnostic, buffer_bytes: "private-argument" },
])(
  "rejects content-bearing or unrecognized native diagnostics",
  async (value) => {
    helper.diagnostic = value;
    const reader = createReader();
    try {
      await expect(reader.read([row])).rejects.toThrow("invalid response");
    } finally {
      await reader.close();
    }
  },
);
