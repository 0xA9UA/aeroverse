// MMA FILE SUMMARY
// Purpose: Exposes target-free console observation through the one-shot CLI.
// Public interface: registerConsoleObservationCommands().
// Collaborators: Shared application service, JSON input reader and cancellation owner.
// Invariants: CLI and MCP execute the same operations; only CLI resolves relative capture paths.
import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { parseCliJsonInput, resolveCliJsonPaths } from "../cliJsonInput.js";
import { logCliCommand } from "../cliLogging.js";
import { createConsoleObservationService } from "../composition/consoleObservation.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { ConsoleObservationOperation } from "../application/ConsoleObservationService.js";

export const registerConsoleObservationCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createConsoleObservationService();
  const register = (
    command: string,
    operation: ConsoleObservationOperation,
    description: string,
  ): void => {
    cli.command(command, {
      description,
      options: z.object({
        input: z
          .string()
          .describe(
            "Inline JSON or a local JSON file containing the MCP input object",
          ),
      }),
      run: ({ options }) =>
        withCommandCancellation((signal) =>
          logCliCommand(logger, command, async () => {
            const input = await parseCliJsonInput(options.input, operation);
            if (!input.ok) return input.error;
            const value =
              operation === "inspect_console_network_capture"
                ? resolveCliJsonPaths(input.value, [["capture_path"]])
                : input.value;
            const result = await service.execute(operation, value, { signal });
            return result.ok
              ? result.value
              : projectAnalysisError(result.error);
          }),
        ),
    });
  };
  register(
    CLI_COMMANDS.inspectConsoleNetworkCapture,
    "inspect_console_network_capture",
    "Inspect retained PCAP/PCAPNG console traffic with source byte provenance",
  );
  register(
    CLI_COMMANDS.observeConsoleDebugger,
    "observe_console_debugger",
    "Collect bounded console debugger stops, registers and selected memory",
  );
  register(
    CLI_COMMANDS.correlateConsoleObservations,
    "correlate_console_observations",
    "Correlate declared console actions, code, IPC and packets with explicit clock uncertainty",
  );
};
