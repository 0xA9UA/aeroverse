// MMA FILE SUMMARY
// Purpose: Wires built-in console observation adapters into one shared application service.
// Public interface: createConsoleObservationService().
// Collaborators: Native packet decoder, bounded debugger adapter and ConsoleObservationService.
// Invariants: Construction performs no filesystem reads, connections or target acquisition.
import { ConsoleObservationService } from "../application/ConsoleObservationService.js";
import { ConsoleNetworkCaptureAdapter } from "../console/network/ConsoleNetworkCaptureAdapter.js";
import { ConsoleDebuggerAdapter } from "../console/debugger/ConsoleDebuggerAdapter.js";
import type { Evidence } from "../domain/evidence.js";

export const createConsoleObservationService = (
  evidenceById?: (id: string) => Evidence | undefined,
): ConsoleObservationService =>
  new ConsoleObservationService(
    new ConsoleNetworkCaptureAdapter(),
    new ConsoleDebuggerAdapter(),
    evidenceById,
  );
