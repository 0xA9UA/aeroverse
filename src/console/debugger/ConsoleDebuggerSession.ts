/** MMA FILE SUMMARY
 * Purpose: Owns one explicitly selected live RSP observation session and its breakpoint lifecycle.
 * Responsibilities: Negotiation, deadlines, repeated execution, reply synchronization and bounded cleanup.
 * Collaborators: RspConnection owns framing; ConsoleDebuggerCollector owns retained observations.
 * Invariants: Never owns the target process; failed breakpoint removal remains explicit in the report.
 */
import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisProtocolError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  ObserveConsoleDebuggerInput,
  ConsoleDebuggerObservation,
  ConsoleDebuggerRegister,
  ConsoleDebuggerStop,
} from "../../domain/consoleDebugger.js";
import {
  ConsoleDebuggerCollector,
  debuggerErrorMessage,
  debuggerStopSignal,
  expectDebuggerReply,
  isDebuggerStop,
} from "./ConsoleDebuggerCollector.js";
import { RspConnection, RspFailure } from "./RspConnection.js";
const OPERATION = "observe_console_debugger";
type Hook = ObserveConsoleDebuggerInput["hooks"][number];
const breakpointCommand = (insert: boolean, hook: Hook): string =>
  `${insert ? "Z" : "z"}0,${BigInt(hook.address).toString(16)},${hook.instruction_size}`;
/** A call owns its socket and explicitly declared exclusive hook set, never an emulator or hardware process. */
export class ConsoleDebuggerSession {
  readonly #started = performance.now();
  readonly #observeUntil: number;
  readonly report: ConsoleDebuggerObservation;
  readonly #collector: ConsoleDebuggerCollector;
  readonly #installed = new Map<string, Hook>();
  #connection!: RspConnection;
  #halted = false;
  #pendingCommand = false;
  #runningRequested = false;
  constructor(
    readonly input: ObserveConsoleDebuggerInput,
    registers: readonly ConsoleDebuggerRegister[],
    readonly options?: ExecutionOptions,
  ) {
    this.#observeUntil = this.#started + input.duration_ms;
    this.report = {
      observation_id: randomUUID(),
      provider: input.provider,
      endpoint: input.endpoint,
      target: input.target,
      target_identity: "caller-declared-not-authenticated-by-stub",
      authority:
        input.provider === "dolphin"
          ? "emulator"
          : input.provider === "openocd"
            ? "hardware-gdbstub"
            : "unverified-gdbstub",
      started_at: new Date().toISOString(),
      ended_at: "",
      completion: "completed",
      failure: null,
      negotiated_features: [],
      stops: [],
      cleanup: {
        status: "complete",
        remaining_breakpoints: [],
        run_state: "unknown",
        reason: null,
      },
      limitations: [
        "Endpoint protocol does not authenticate the caller-declared game, profile, processor or runtime version.",
        "No thread/inferior selection is performed; samples use the stub's current context. Per-CPU endpoint selection requires independent verification.",
        "Stops use host monotonic/wall clocks; guest time and action causation require separate correlation evidence.",
        "If an initially stopped stub ignores interrupt, a stop-status query is used; its signal may be synthetic and does not establish a guest exception cause.",
        "Halted-observed describes the stop before disconnect; the stub's disconnect policy may subsequently resume execution.",
        "Breakpoints and pauses perturb timing. Guest IPC/send labels are caller-specified addresses, not inferred API semantics.",
        "Continuing from an owned breakpoint temporarily removes it and single-steps one instruction; those stops are retained as step-over observations.",
        "Only explicit register-selected memory is sampled. No direct memory/register writes, resets, monitor commands or target kills are issued; stub software breakpoints may patch code.",
        ...(input.provider === "dolphin"
          ? [
              "Dolphin exposes the guest PPC context, not native host threads or an IOS ARM CPU. Query stop signals do not prove guest exceptions.",
            ]
          : [
              "Register layout, selected processor and hardware/emulator provenance require independent runtime verification; OpenOCD board configuration may itself halt or reset on attachment.",
            ]),
      ],
    };
    this.#collector = new ConsoleDebuggerCollector(
      { input, registers, report: this.report, started: this.#started },
      (command) => this.#request(command),
    );
  }
  async run(): Promise<Result<ConsoleDebuggerObservation, AnalysisError>> {
    try {
      this.#connection = await RspConnection.open(
        this.input.endpoint,
        this.#deadline(),
        this.options?.signal,
      );
    } catch (error) {
      if (error instanceof RspFailure && error.kind === "cancelled")
        return err(new AnalysisCancelledError(OPERATION));
      if (error instanceof RspFailure && error.kind === "timeout")
        return err(
          new AnalysisTimeoutError(OPERATION, this.input.command_timeout_ms),
        );
      return err(
        new AnalysisProtocolError(
          `Debugger connection failed: ${debuggerErrorMessage(error)}`,
        ),
      );
    }
    try {
      await this.#negotiate();
      await this.#initialStop();
      for (const hook of this.input.hooks) await this.#insertHook(hook);
      await this.#trace();
    } catch (error) {
      this.report.completion =
        error instanceof RspFailure && error.kind === "cancelled"
          ? "cancelled"
          : error instanceof RspFailure && error.kind === "timeout"
            ? "timeout"
            : "partial";
      this.report.failure = debuggerErrorMessage(error);
    } finally {
      await this.#cleanup();
    }
    return ok(this.report);
  }
  #deadline(): number {
    return Math.min(
      this.#observeUntil,
      performance.now() + this.input.command_timeout_ms,
    );
  }
  async #request(command: string): Promise<string> {
    const expires = this.#deadline();
    if (this.options?.signal?.aborted)
      throw new RspFailure("cancelled", "Debugger observation cancelled.");
    if (performance.now() >= expires)
      throw new RspFailure("timeout", "Debugger response deadline exceeded.");
    this.#pendingCommand = true;
    let response = await this.#connection.request(
      command,
      expires,
      this.options?.signal,
    );
    // A delayed interrupt stop can precede the stop-status query response.
    while (command !== "?" && isDebuggerStop(response))
      response = await this.#connection.packet(expires, this.options?.signal);
    this.#pendingCommand = false;
    return response;
  }
  async #negotiate(): Promise<void> {
    const supported = await this.#request("qSupported:");
    if (/^E[0-9a-fA-F]+$/.test(supported))
      throw new RspFailure("protocol", "Stub rejected capability negotiation.");
    this.report.negotiated_features =
      supported === "" ? [] : supported.split(";");
    const packetSize = this.report.negotiated_features.find((feature) =>
      /^PacketSize=[0-9a-fA-F]+$/.test(feature),
    );
    if (packetSize !== undefined) {
      const bytes = Number.parseInt(packetSize.slice("PacketSize=".length), 16);
      if (!Number.isSafeInteger(bytes) || bytes < 16)
        throw new RspFailure(
          "protocol",
          "Advertised packet size cannot carry the required debugger commands.",
        );
      this.#collector.memoryChunkBytes = Math.min(
        this.#collector.memoryChunkBytes,
        Math.floor(bytes / 2),
      );
    }
    if (this.report.negotiated_features.includes("QStartNoAckMode+")) {
      const response = await this.#request("QStartNoAckMode");
      if (response === "OK") this.#connection.setNoAck();
      else if (response !== "")
        throw new RspFailure(
          "protocol",
          "Stub rejected advertised no-ack mode.",
        );
    }
    if (this.input.provider === "dolphin") {
      const host = await this.#request("qHostInfo");
      const fields = new Set(host.split(";"));
      if (
        host !== "" &&
        (!fields.has("endian:big") || !fields.has("ptrsize:4"))
      )
        throw new RspFailure(
          "protocol",
          "Stub host information contradicts the Dolphin PPC layout.",
        );
    }
  }
  async #initialStop(): Promise<void> {
    this.#connection.interrupt();
    let initial: string;
    let reason: ConsoleDebuggerStop["reason"] = "initial-interrupt";
    try {
      initial = await this.#connection.packet(
        Math.min(this.#deadline(), performance.now() + 100),
        this.options?.signal,
      );
    } catch (error) {
      if (!(error instanceof RspFailure) || error.kind !== "timeout")
        throw error;
      initial = await this.#request("?");
      reason = "initial-stop-query";
    }
    await this.#collect(initial, reason);
  }
  async #collect(
    reply: string,
    reason: ConsoleDebuggerStop["reason"],
  ): Promise<void> {
    const signal = debuggerStopSignal(reply);
    this.#halted = true;
    this.#runningRequested = false;
    await this.#collector.collect(signal, reason);
  }
  async #insertHook(hook: Hook): Promise<void> {
    // A lost acknowledgment does not prove that the remote side made no change.
    this.#installed.set(hook.address, hook);
    const response = await this.#request(breakpointCommand(true, hook));
    if (response === "OK") return;
    if (response === "" || /^E[0-9a-fA-F]+$/.test(response))
      this.#installed.delete(hook.address);
    expectDebuggerReply(response, "breakpoint insertion");
    throw new RspFailure("protocol", "Unexpected breakpoint insertion reply.");
  }
  #resume(step: boolean): void {
    if (this.options?.signal?.aborted)
      throw new RspFailure("cancelled", "Debugger observation cancelled.");
    this.#connection.send(step ? "s" : "c");
    this.#runningRequested = true;
    this.#halted = false;
  }
  async #stepOver(hook: Hook): Promise<void> {
    if ((await this.#request(breakpointCommand(false, hook))) !== "OK")
      throw new RspFailure(
        "protocol",
        "Could not remove breakpoint before single-step.",
      );
    this.#installed.delete(hook.address);
    this.#resume(true);
    await this.#collect(
      await this.#connection.packet(this.#deadline(), this.options?.signal),
      "step-over",
    );
    await this.#insertHook(hook);
  }
  async #trace(): Promise<void> {
    while (
      this.report.stops.length < this.input.max_stops &&
      performance.now() < this.#observeUntil
    ) {
      const pc = this.report.stops.at(-1)?.pc;
      const hook = [...this.#installed.values()].find(
        (candidate) =>
          pc !== null &&
          pc !== undefined &&
          BigInt(candidate.address) === BigInt(pc),
      );
      if (hook) {
        await this.#stepOver(hook);
        if (
          this.report.stops.length >= this.input.max_stops ||
          performance.now() >= this.#observeUntil
        )
          break;
      }
      this.#resume(false);
      let reply: string;
      try {
        reply = await this.#connection.packet(
          this.#observeUntil,
          this.options?.signal,
        );
      } catch (error) {
        if (
          error instanceof RspFailure &&
          error.kind === "timeout" &&
          performance.now() >= this.#observeUntil
        )
          break;
        throw error;
      }
      if (/^[WX][0-9a-fA-F]{2}/.test(reply)) {
        this.report.limitations.push(
          "Stub reported target exit; final run state is unknown.",
        );
        break;
      }
      await this.#collect(reply, "stop-reply");
    }
  }
  async #synchronizeCleanup(deadline: number): Promise<void> {
    if (this.#pendingCommand) {
      // A reply may block the stub until acknowledged; do not issue a new command before draining it.
      let response = await this.#connection.packet(deadline);
      while (isDebuggerStop(response))
        response = await this.#connection.packet(deadline);
      this.#pendingCommand = false;
    }
    if (this.#halted) return;
    this.#connection.interrupt();
    if (!this.#runningRequested) this.#connection.send("?");
    for (;;) {
      const response = await this.#connection.packet(deadline);
      if (isDebuggerStop(response)) {
        debuggerStopSignal(response);
        break;
      }
    }
    this.#halted = true;
    this.#runningRequested = false;
  }
  async #removeHooks(deadline: number, problems: string[]): Promise<void> {
    for (const [address, hook] of this.#installed) {
      let response = await this.#connection.request(
        breakpointCommand(false, hook),
        deadline,
      );
      while (isDebuggerStop(response))
        response = await this.#connection.packet(deadline);
      if (response === "OK") this.#installed.delete(address);
      else
        problems.push(`Breakpoint removal was not acknowledged at ${address}.`);
    }
  }
  async #cleanup(): Promise<void> {
    const deadline = performance.now() + this.input.cleanup_timeout_ms;
    const problems: string[] = [];
    try {
      await this.#synchronizeCleanup(deadline);
      await this.#removeHooks(deadline, problems);
      if (this.input.resume_on_finish) {
        await this.#resumeAndDetach(deadline);
        this.#halted = false;
        this.report.cleanup.run_state = "running-requested";
      } else this.report.cleanup.run_state = "halted-observed";
    } catch (error) {
      problems.push(debuggerErrorMessage(error));
    } finally {
      this.#connection.close();
    }
    this.report.cleanup.remaining_breakpoints = [...this.#installed.keys()];
    if (problems.length > 0 || this.#installed.size > 0) {
      this.report.cleanup.status = "incomplete";
      this.report.cleanup.reason =
        problems.join("; ") || "Breakpoint cleanup remains unresolved.";
    }
    this.report.ended_at = new Date().toISOString();
  }
  async #resumeAndDetach(deadline: number): Promise<void> {
    // Standard RSP detach resumes execution and acknowledges processing before socket close.
    // melonDS needs this to leave its debugger loop reliably; Dolphin has no D handler.
    if (this.input.provider !== "dolphin") {
      let response = await this.#connection.request("D", deadline);
      while (isDebuggerStop(response))
        response = await this.#connection.packet(deadline);
      if (response === "OK") return;
      if (response !== "")
        throw new RspFailure("protocol", "Stub refused resume-and-detach.");
    }
    this.#connection.send("c");
  }
}
