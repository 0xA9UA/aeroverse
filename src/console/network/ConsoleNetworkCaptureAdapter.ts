// MMA FILE SUMMARY
// Purpose: Produces bounded, source-bound offline packet evidence from one stable file snapshot.
// Public interface: ConsoleNetworkCaptureAdapter.inspect().
// Collaborators: readStableArtifact acquires provenance; container and packet decoders own binary formats.
// Invariants: Full container validation precedes success; selection preserves caller order; no network side effects.
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { setImmediate } from "node:timers/promises";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import {
  CONSOLE_NETWORK_CAPTURE_LIMITS,
  consoleNetworkCaptureSchema,
  inspectConsoleNetworkCaptureInputSchema,
  type ConsoleNetworkCapture,
  type ConsoleNetworkPacket,
  type InspectConsoleNetworkCaptureInput,
} from "../../domain/consoleNetworkCapture.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  CaptureContainerFailure,
  openCaptureContainer,
  type CaptureRecord,
  type CaptureContainer,
} from "./CaptureContainers.js";
import { dissectPacket, type PacketDissection } from "./PacketDissection.js";
import { inspectPacketMessages } from "./PacketMessages.js";
import type { PacketPayload } from "./TcpStreamAssembly.js";

const OPERATION = "inspect_console_network_capture";
const resourceFailure = (
  resource: "file-size" | "memory" | "transport",
  reason: string,
): AnalysisResourceConstraintError =>
  new AnalysisResourceConstraintError(OPERATION, resource, reason, {
    maximum_input_bytes: CONSOLE_NETWORK_CAPTURE_LIMITS.inputBytes,
    maximum_output_bytes: CONSOLE_NETWORK_CAPTURE_LIMITS.outputBytes,
    maximum_interfaces_per_section:
      CONSOLE_NETWORK_CAPTURE_LIMITS.interfacesPerSection,
  });
const invalid = (
  message: string,
  path: (string | number)[] = ["capture_path"],
): AnalysisInputError =>
  new AnalysisInputError(OPERATION, undefined, [
    { path, reason: "invalid_format", message },
  ]);

/** No process, network, capture driver, replay endpoint, or privileged dependency is used. */
export class ConsoleNetworkCaptureAdapter {
  async inspect(
    input: InspectConsoleNetworkCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<ConsoleNetworkCapture, AnalysisError>> {
    try {
      options?.signal?.throwIfAborted();
      const parsed = inspectConsoleNetworkCaptureInputSchema.safeParse(input);
      if (!parsed.success)
        return err(
          invalid(
            "Expected capture_path, optional nonempty packet_ordinals, and optional include_payload boolean.",
            [],
          ),
        );
      const request = parsed.data;
      if (!isAbsolute(request.capture_path))
        return err(invalid("Select an absolute local capture path."));
      if (
        request.packet_ordinals !== undefined &&
        new Set(request.packet_ordinals).size !== request.packet_ordinals.length
      )
        return err(
          invalid("Packet ordinals must not contain duplicates.", [
            "packet_ordinals",
          ]),
        );
      const snapshot = await readStableArtifact(
        request.capture_path,
        CONSOLE_NETWORK_CAPTURE_LIMITS.inputBytes,
        options?.signal,
      );
      const container = openCaptureContainer(snapshot.bytes);
      const selection = await collectPackets(
        container,
        snapshot,
        request,
        options,
      );
      const missing = request.packet_ordinals?.find(
        (ordinal) => !selection.packets.has(ordinal),
      );
      if (missing !== undefined)
        return err(
          invalid(
            `Packet ordinal ${missing} is outside this capture's ${selection.coverage.total_packets} packet records.`,
            ["packet_ordinals"],
          ),
        );
      const report = projectCapture(request, snapshot, container, selection);
      options?.signal?.throwIfAborted();
      if (
        Buffer.byteLength(JSON.stringify(report)) >
        CONSOLE_NETWORK_CAPTURE_LIMITS.outputBytes
      )
        throw resourceFailure(
          "transport",
          "Complete report exceeds the output byte budget; select fewer packet_ordinals.",
        );
      const checked = consoleNetworkCaptureSchema.safeParse(report);
      if (!checked.success)
        return err(
          new AnalysisOutputError(
            OPERATION,
            "Native capture decoder violated its report contract.",
            { cause: checked.error },
          ),
        );
      return ok(checked.data);
    } catch (cause) {
      return err(captureFailure(input.capture_path, cause, options));
    }
  }
}

type CaptureRequest = ReturnType<
  typeof inspectConsoleNetworkCaptureInputSchema.parse
>;
type CaptureSnapshot = Awaited<ReturnType<typeof readStableArtifact>>;
type PacketSelection = {
  packets: Map<number, ConsoleNetworkPacket>;
  payloads: PacketPayload[];
  outputBytes: number;
  coverage: ConsoleNetworkCapture["coverage"];
};
/** Complete container traversal owns selection, cancellation and retained packet budgets. */
async function collectPackets(
  container: CaptureContainer,
  snapshot: CaptureSnapshot,
  request: CaptureRequest,
  options?: ExecutionOptions,
): Promise<PacketSelection> {
  const selected =
    request.packet_ordinals === undefined
      ? null
      : new Set(request.packet_ordinals);
  const packets = new Map<number, ConsoleNetworkPacket>();
  const payloads: PacketPayload[] = [];
  let outputBytes = 2048 + Buffer.byteLength(request.capture_path);
  const coverage: ConsoleNetworkCapture["coverage"] = {
    container: "complete",
    total_packets: 0,
    selected_packets: 0,
    unknown_blocks: 0,
    truncated_packets: 0,
    fragmented_packets: 0,
    unsupported_link_packets: 0,
    payload_release: request.include_payload ? "hex" : "digest_only",
    reassembly: "bounded-selected-tcp",
    decryption: "not_attempted",
  };
  let records = 0;
  for (const record of container.records) {
    // Yield for cancellation even through captures consisting solely of metadata/unknown blocks.
    if ((records++ & 255) === 0) {
      await setImmediate();
      options?.signal?.throwIfAborted();
    }
    if (record === null) continue;
    coverage.total_packets++;
    const dissection = dissectPacket(record);
    if (record.bytes.length < record.originalLength)
      coverage.truncated_packets++;
    if (dissection.fragmentation.state === "fragmented")
      coverage.fragmented_packets++;
    if (!dissection.supportedLink) coverage.unsupported_link_packets++;
    if (selected !== null && !selected.has(record.ordinal)) continue;
    const retained = selectPacket(record, dissection, {
      sha256: snapshot.sha256,
      includePayload: request.include_payload,
      outputBytes,
    });
    outputBytes += retained.bytes;
    packets.set(record.ordinal, retained.packet);
    payloads.push({ packet: retained.packet, payload: dissection.payload });
  }
  coverage.selected_packets = packets.size;
  coverage.unknown_blocks = container.statistics.unknownBlocks;
  return { packets, payloads, outputBytes, coverage };
}
function selectPacket(
  record: CaptureRecord,
  dissection: PacketDissection,
  selection: { sha256: string; includePayload: boolean; outputBytes: number },
): { packet: ConsoleNetworkPacket; bytes: number } {
  if (
    selection.includePayload &&
    selection.outputBytes + (dissection.payload?.length ?? 0) * 2 >
      CONSOLE_NETWORK_CAPTURE_LIMITS.outputBytes
  )
    throw resourceFailure(
      "transport",
      "Selected payload hex exceeds the output byte budget; select packet_ordinals or omit include_payload.",
    );
  const packet = projectPacket(
    record,
    dissection,
    selection.sha256,
    selection.includePayload,
  );
  const bytes = Buffer.byteLength(JSON.stringify(packet)) + 1;
  if (
    selection.outputBytes + bytes >
    CONSOLE_NETWORK_CAPTURE_LIMITS.outputBytes
  )
    throw resourceFailure(
      "transport",
      "Selected packet metadata exceeds the output byte budget; select fewer packet_ordinals.",
    );
  return { packet, bytes };
}
function projectCapture(
  request: CaptureRequest,
  snapshot: CaptureSnapshot,
  container: CaptureContainer,
  selection: PacketSelection,
): ConsoleNetworkCapture {
  return {
    artifact: {
      path: request.capture_path,
      sha256: snapshot.sha256,
      bytes: snapshot.bytes.length,
    },
    format: container.format,
    decoder: { id: "rea-native-pcap", version: "1" },
    packets:
      request.packet_ordinals === undefined
        ? [...selection.packets.values()]
        : request.packet_ordinals.map((ordinal) =>
            selection.packets.get(ordinal)!,
          ),
    ...inspectPacketMessages(
      selection.payloads,
      CONSOLE_NETWORK_CAPTURE_LIMITS.outputBytes - selection.outputBytes,
    ),
    coverage: selection.coverage,
    limitations: [
      "Complete refers to container traversal, not completeness of the original capture session, protocol coverage, or packet delivery.",
      "Capture timestamps retain the producer's declared origin and resolution; clock accuracy and alignment to runtime/action events are not established.",
      "Bounded TCP reconstruction covers selected packets and records gaps, agreeing retransmissions and overlap conflicts; IP fragments and transport checksums are not reconstructed or validated.",
      "Only strict plaintext HTTP/1.x framing and UDP DNS are interpreted. TLS, transfer/content decompression, application state and request/response pairing remain outside coverage; unknown payloads may be encrypted.",
      "Capture comments, interface names, packet options, drop statistics, name-resolution records and decryption-secret blocks are not projected; no producer identity or packet-loss guarantee is inferred.",
      ...(container.statistics.unknownBlocks === 0
        ? []
        : [
            "Non-packet/unknown pcapng blocks were structurally traversed but not interpreted; custom packet encodings are outside decoded packet coverage.",
          ]),
    ],
  };
}

const projectPacket = (
  record: CaptureRecord,
  decoded: PacketDissection,
  sha256: string,
  includePayload: boolean,
): ConsoleNetworkPacket => ({
  id: `sha256:${sha256}/packet:${record.ordinal}`,
  ordinal: record.ordinal,
  offset: record.offset,
  data_offset: record.dataOffset,
  timestamp_ns: record.timestampNs,
  timestamp_ticks: record.timestampTicks,
  timestamp_resolution:
    record.timestampTicks === null ? null : record.interface.resolution,
  captured_length: record.bytes.length,
  original_length: record.originalLength,
  interface_id: record.interface.id,
  link_type: record.interface.linkType,
  snap_length: record.interface.snapLength,
  network: decoded.network,
  flow: decoded.flow,
  tcp: decoded.tcp,
  fragmentation: decoded.fragmentation,
  truncated: record.bytes.length < record.originalLength,
  encryption: decoded.encryption,
  payload_state: decoded.payload_state,
  payload_offset: decoded.payloadOffset,
  payload_bytes: decoded.payload?.length ?? null,
  payload_sha256:
    decoded.payload === null
      ? null
      : createHash("sha256").update(decoded.payload).digest("hex"),
  payload_hex:
    includePayload && decoded.payload !== null
      ? decoded.payload.toString("hex")
      : null,
  limitations: decoded.limitations,
});

const captureFailure = (
  path: string,
  cause: unknown,
  options?: ExecutionOptions,
): AnalysisError => {
  if (options?.signal?.aborted)
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof CaptureContainerFailure)
    return cause.resource
      ? resourceFailure("memory", cause.message)
      : invalid(`${cause.message} At capture byte offset ${cause.offset}.`);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "integrity")
      return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
        cause,
      });
    if (cause.reason === "limit")
      return resourceFailure("file-size", cause.message);
    if (cause.reason === "cancelled")
      return new AnalysisCancelledError(OPERATION, { cause });
    if (cause.reason === "path" || cause.reason === "format")
      return invalid(cause.message);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (["ENOENT", "ENOTDIR"].includes(String(cause.code)))
      return invalid(
        `Selected capture could not be read (${String(cause.code)}).`,
      );
  }
  return new ProviderAdapterError("rea-native-pcap", OPERATION, {
    cause,
    diagnostics: {
      capture_path: path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};
