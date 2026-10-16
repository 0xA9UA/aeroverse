// MMA FILE SUMMARY
// Purpose: Binds console observation to exact named MCP contracts and session Evidence retention.
// Public interface: registerConsoleObservationTools().
// Collaborators: ConsoleObservationService and shared contract/admission/delivery handlers.
// Invariants: No binary target is required; SDK schema and application validation stay aligned.
import type { Logger } from "pino";
import type { ConsoleObservationService } from "../application/ConsoleObservationService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

export const registerConsoleObservationTools = (
  server: EvidenceMcpServer,
  service: ConsoleObservationService,
  logger: Logger,
  options: {
    recordEvidence?: EvidenceWriter["recordEvidence"] | undefined;
    withAdmittedAnalysis?: WithAdmittedAnalysis | undefined;
  } = {},
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    options.recordEvidence,
    options.withAdmittedAnalysis,
  );
  const capture = toolContract("inspect_console_network_capture");
  server.registerTool(
    capture.name,
    toolRegistrationOptions(capture),
    handler(capture),
  );
  const debuggerObservation = toolContract("observe_console_debugger");
  server.registerTool(
    debuggerObservation.name,
    toolRegistrationOptions(debuggerObservation),
    handler(debuggerObservation),
  );
  const correlation = toolContract("correlate_console_observations");
  server.registerTool(
    correlation.name,
    toolRegistrationOptions(correlation),
    handler(correlation),
  );
};
