// MMA FILE SUMMARY
// Purpose: Validates console observations and composes shared CLI/MCP Evidence.
// Responsibilities: Preserve measured capture identity, live uncertainty and retained correlation links.
// Public interface: ConsoleObservationService.execute() and ConsoleObservationOperation.
// Collaborators: Capture/debugger ports and pure correlation semantics.
// Invariants: Caller-declared game hashes never become measured live subjects; partial live cleanup remains visible.
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "./AnalysisProvider.js";
import type {
  ConsoleDebuggerObservationPort,
  ConsoleNetworkCapturePort,
} from "./ConsoleObservationPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
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
import { correlateConsoleObservations } from "../domain/consoleCorrelation.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { consoleCorrelationEvidenceContext } from "./consoleObservationEvidence.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { jsonObjectSchema, jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  CONSOLE_CAPTURE_PROVIDER_IDENTITY,
  CONSOLE_DEBUGGER_PROVIDER_IDENTITY,
  CONSOLE_CORRELATION_PROVIDER_IDENTITY,
} from "../console/providerIdentities.js";

export type ConsoleObservationOperation =
  | "inspect_console_network_capture"
  | "observe_console_debugger"
  | "correlate_console_observations";

export class ConsoleObservationService {
  constructor(
    readonly capture: ConsoleNetworkCapturePort,
    readonly debuggerObservation: ConsoleDebuggerObservationPort,
    readonly evidenceById?: (id: string) => Evidence | undefined,
  ) {}

  async execute(
    operation: ConsoleObservationOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    switch (operation) {
      case "inspect_console_network_capture":
        return this.inspectCapture(input, options);
      case "observe_console_debugger":
        return this.observeDebugger(input, options);
      case "correlate_console_observations":
        return this.correlate(input, options);
    }
  }

  private async inspectCapture(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "inspect_console_network_capture";
    const parsed = inspectConsoleNetworkCaptureInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, rawInput),
      );
    const input = parsed.data;
    if (!isAbsolute(input.capture_path))
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["capture_path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    if (
      input.packet_ordinals !== undefined &&
      new Set(input.packet_ordinals).size !== input.packet_ordinals.length
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["packet_ordinals"],
            reason: "invalid_value",
            message: "Each requested packet ordinal must occur once.",
          },
        ]),
      );
    const decoded = await this.capture.inspect(input, options);
    if (!decoded.ok) return decoded;
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    const parsedReport = consoleNetworkCaptureSchema.safeParse(decoded.value);
    if (!parsedReport.success)
      return err(
        new AnalysisOutputError(
          operation,
          "Capture adapter returned malformed packet evidence.",
        ),
      );
    const report = parsedReport.data;
    const expectedOrdinals =
      input.packet_ordinals ?? report.packets.map((_, index) => index);
    if (
      report.artifact.path !== input.capture_path ||
      report.coverage.selected_packets !== report.packets.length ||
      report.packets.length !== expectedOrdinals.length ||
      report.packets.some(
        (packet, index) => packet.ordinal !== expectedOrdinals[index],
      ) ||
      (input.packet_ordinals === undefined &&
        report.packets.length !== report.coverage.total_packets) ||
      report.coverage.payload_release !==
        (input.include_payload ? "hex" : "digest_only")
    )
      return err(
        new AnalysisOutputError(
          operation,
          "Capture adapter changed the source, requested packet sequence or payload release policy.",
        ),
      );
    return ok(
      createEvidence(
        {
          path: report.artifact.path,
          sha256: report.artifact.sha256,
          format: "file",
        },
        { ...CONSOLE_CAPTURE_PROVIDER_IDENTITY, ...report.decoder },
        {
          predicateType: "rea.console-network-capture",
          operation,
          parameters: jsonObjectSchema.parse(input),
          result: jsonValueSchema.parse(report),
          confidence: "observed",
          authority: "historical-reference",
          limitations: report.limitations,
          locations: [{ kind: "artifact-path", path: report.artifact.path }],
        },
      ),
    );
  }

  private async observeDebugger(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const operation = "observe_console_debugger";
    const parsed = observeConsoleDebuggerInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, rawInput),
      );
    const input = parsed.data;
    const observed = await this.debuggerObservation.observe(input, options);
    if (!observed.ok) return observed;
    // A successful partial observation can retain target changes and cleanup
    // failures after cancellation; replacing it with a generic abort loses facts.
    const parsedReport = consoleDebuggerObservationSchema.safeParse(
      observed.value,
    );
    if (!parsedReport.success)
      return err(
        new AnalysisOutputError(
          operation,
          "Debugger adapter returned malformed observation evidence.",
        ),
      );
    const report = parsedReport.data;
    if (
      report.provider !== input.provider ||
      JSON.stringify(report.endpoint) !== JSON.stringify(input.endpoint) ||
      JSON.stringify(report.target) !== JSON.stringify(input.target)
    )
      return err(
        new AnalysisOutputError(
          operation,
          "Debugger adapter changed the caller-selected provider, endpoint or declared target identity.",
        ),
      );
    const limitations = [...report.limitations];
    if (report.cleanup.status === "incomplete")
      limitations.push(
        "Debugger cleanup is incomplete; inspect cleanup.remaining_breakpoints and cleanup.run_state before using the target again.",
      );
    return ok(
      createEvidence(undefined, CONSOLE_DEBUGGER_PROVIDER_IDENTITY, {
        predicateType: "rea.console-debugger-observation",
        operation,
        parameters: jsonObjectSchema.parse(input),
        result: jsonValueSchema.parse(report),
        confidence: "observed",
        authority: "controlled-replay",
        subjectUnavailableReason:
          "The game hash and runtime identity are caller declarations; this debugger stub does not measure or authenticate a game image or hardware identity.",
        limitations,
        locations: [
          ...new Set(
            report.stops.flatMap(({ pc }) => (pc === null ? [] : [pc])),
          ),
        ].map((address) => ({ kind: "address" as const, address })),
      }),
    );
  }

  private correlate(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Result<Evidence, AnalysisError> {
    const operation = "correlate_console_observations";
    const parsed = correlateConsoleObservationsInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return err(
        analysisInputErrorFromIssues(operation, parsed.error.issues, rawInput),
      );
    const input = parsed.data;
    const correlated = correlateConsoleObservations(input);
    if (!correlated.ok) return correlated;
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    const parsedReport = consoleCorrelationSchema.safeParse(correlated.value);
    if (!parsedReport.success)
      return err(
        new AnalysisOutputError(
          operation,
          "Correlation returned malformed console evidence.",
        ),
      );
    const report = parsedReport.data;
    const context = consoleCorrelationEvidenceContext(
      input,
      report,
      this.evidenceById,
    );
    return ok(
      createEvidence(undefined, CONSOLE_CORRELATION_PROVIDER_IDENTITY, {
        predicateType: "rea.console-observation-correlation",
        operation,
        parameters: context.parameters,
        result: jsonValueSchema.parse(report),
        confidence: "derived",
        authority: "analyst-inference",
        subjectUnavailableReason:
          "This derived graph combines declared events and source digests; no single measured artifact is its subject.",
        limitations: context.limitations,
        evidenceLinks: context.evidenceLinks,
      }),
    );
  }
}
