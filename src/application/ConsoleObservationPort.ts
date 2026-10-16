// MMA FILE SUMMARY
// Purpose: Isolates console capture decoding and debugger transport from application Evidence.
// Public interface: ConsoleNetworkCapturePort and ConsoleDebuggerObservationPort.
// Collaborators: Domain console schemas and adapter-owned scoped resources.
// Invariants: Ports return validated observations; they do not acquire binary sessions.
import type { ExecutionOptions } from "./AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Result } from "../domain/result.js";
import type {
  ConsoleNetworkCapture,
  InspectConsoleNetworkCaptureInput,
} from "../domain/consoleNetworkCapture.js";
import type {
  ConsoleDebuggerObservation,
  ObserveConsoleDebuggerInput,
} from "../domain/consoleDebugger.js";

/** Offline retained packet capture decoding with measured source identity. */
export interface ConsoleNetworkCapturePort {
  inspect(
    input: InspectConsoleNetworkCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<ConsoleNetworkCapture, AnalysisError>>;
}

/** One bounded debugger connection; the adapter owns and releases its hooks. */
export interface ConsoleDebuggerObservationPort {
  observe(
    input: ObserveConsoleDebuggerInput,
    options?: ExecutionOptions,
  ): Promise<Result<ConsoleDebuggerObservation, AnalysisError>>;
}
