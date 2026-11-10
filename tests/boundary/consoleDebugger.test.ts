/** MMA FILE SUMMARY
 * Purpose: Exercises debugger observation across a real local socket with controlled RSP peers.
 * Responsibilities: Framing, CPU register interpretation, repeated stops, bounded capture and lifecycle failures.
 * Invariants: Simulated stub behavior establishes protocol handling, not console/emulator/hardware support.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { input, ppcFixture, stub } from "../fixtures/consoleDebugger.js";
import {
  ConsoleDebuggerAdapter,
  MELONDS_ARM_REGISTERS,
} from "../../src/console/debugger/ConsoleDebuggerAdapter.js";
import {
  consoleDebuggerObservationSchema,
  type ObserveConsoleDebuggerInput,
} from "../../src/domain/consoleDebugger.js";

async function observe(
  value: ObserveConsoleDebuggerInput,
  signal?: AbortSignal,
) {
  const result = await new ConsoleDebuggerAdapter().observe(
    value,
    signal === undefined ? undefined : { signal },
  );
  if (!result.ok) throw result.error;
  expect(consoleDebuggerObservationSchema.safeParse(result.value).success).toBe(
    true,
  );
  return result.value;
}
describe("bounded console debugger RSP observation (simulated stubs)", () => {
  it("preserves Dolphin big-endian PPC registers, repeated hook stops, step-over and bounded memory", async () => {
    const remote = await stub(ppcFixture());
    const report = await observe(
      input(remote.endpoint, {
        max_stops: 4,
        breakpoint_scope: "exclusive-session",
        memory_policy: "bytes",
        hooks: [
          {
            label: "guest_send",
            kind: "network",
            address: "0x80001000",
            memory: [
              {
                label: "payload",
                address_register: "r3",
                length_register: "r4",
                length: 4,
              },
            ],
          },
        ],
      }),
    );
    expect(report.completion).toBe("completed");
    expect(report.stops.map((stop) => stop.reason)).toEqual([
      "initial-interrupt",
      "stop-reply",
      "step-over",
      "stop-reply",
    ]);
    expect(
      report.stops[1]!.registers.find((register) => register.name === "r3")!
        .value,
    ).toBe("0x80002000");
    expect(report.stops[1]!.memory).toEqual([
      {
        label: "payload",
        address: "0x80002000",
        requested_bytes: "6",
        bytes: 4,
        sha256: createHash("sha256").update("ABCD").digest("hex"),
        content_base64: Buffer.from("ABCD").toString("base64"),
        truncated: true,
      },
    ]);
    expect(report.cleanup).toMatchObject({
      status: "complete",
      remaining_breakpoints: [],
      run_state: "halted-observed",
    });
    expect(
      remote.peers[0]!.commands.filter((command) => command.startsWith("z0")),
    ).toEqual(["z0,80001000,4", "z0,80001000,4"]);
    expect(remote.peers[0]!.commands).not.toContain("k");
    expect(report.target_identity).toBe(
      "caller-declared-not-authenticated-by-stub",
    );
  });
  it("reassembles fragmented frames, retries a bad checksum and accepts empty unsupported negotiation", async () => {
    const normal = ppcFixture();
    const remote = await stub((command, peer) => {
      if (command === "qSupported:") {
        peer.reply("", { fragmented: true, badChecksum: true });
        return undefined;
      }
      if (command === "qHostInfo") {
        peer.reply("", { fragmented: true });
        return undefined;
      }
      return normal(command, peer);
    });
    const report = await observe(input(remote.endpoint));
    expect(report.negotiated_features).toEqual([]);
    expect(report.stops[0]!.pc).toBe("0x100");
    expect(remote.peers[0]!.acknowledgments).toContain("-");
  });
  it("enters no-ack mode only after advertised support and OK", async () => {
    const normal = ppcFixture({ features: "QStartNoAckMode+;PacketSize=400" });
    const remote = await stub((command, peer) => {
      if (command === "QStartNoAckMode") {
        peer.noAck = true;
        return "OK";
      }
      return normal(command, peer);
    });
    const report = await observe(
      input(remote.endpoint, { resume_on_finish: true }),
    );
    expect(report.cleanup.run_state).toBe("running-requested");
    expect(remote.peers[0]!.commands).toContain("QStartNoAckMode");
    // The transition's OK is acknowledged; following register replies are not.
    expect(
      remote.peers[0]!.acknowledgments.filter((ack) => ack === "+").length,
    ).toBe(3);
  });
  it("keeps caller-selected ARM9/ARM7 identity and explicit little-endian melonDS p numbering", async () => {
    const remote = await stub((command, peer) => {
      if (command === "qSupported:") {
        expect(peer.acknowledgments[0]).toBe("+");
        return "";
      }
      if (command === "D") return "OK";
      if (command === "interrupt") return undefined;
      if (command === "?") return "T05";
      if (/^p[0-9a-f]+$/.test(command))
        return command === "pf"
          ? "00100002"
          : command === "p10"
            ? "3f000000"
            : "78563412";
      throw new Error(`Unmodeled ARM fixture command: ${command}`);
    });
    const report = await observe(
      input(remote.endpoint, {
        provider: "gdb-remote",
        target: {
          platform: "nintendo.nintendo_ds_family",
          processor: "arm9",
          profile: "0.1.1",
          game_build_sha256: "b".repeat(64),
          runtime_version: "simulated-melonds-shape",
        },
        register_map: [...MELONDS_ARM_REGISTERS],
        resume_on_finish: true,
      }),
    );
    expect(report.target.processor).toBe("arm9");
    expect(remote.peers[0]!.commands.at(-1)).toBe("D");
    expect(report.cleanup.run_state).toBe("running-requested");
    expect(report.stops[0]!.reason).toBe("initial-stop-query");
    expect(report.stops[0]!.pc).toBe("0x2001000");
    expect(
      report.stops[0]!.registers.find((register) => register.name === "cpsr")!
        .value,
    ).toBe("0x3f");
    expect(remote.peers[0]!.commands).toContain("p10");
    expect(remote.peers[0]!.commands).not.toContain("p19");
    expect(report.authority).toBe("unverified-gdbstub");
  });
});
describe("console debugger cancellation and cleanup (simulated stubs)", () => {
  it("preserves a pre-attachment cancellation cause without opening the endpoint", async () => {
    const remote = await stub(ppcFixture());
    const cause = new Error("Caller cancelled before attaching");
    const result = await new ConsoleDebuggerAdapter().observe(
      input(remote.endpoint),
      {
        signal: AbortSignal.abort(cause),
      },
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error).toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(result.error.cause).toBe(cause);
    expect(remote.peers).toHaveLength(0);
  });
  it("retains partial registers and resynchronizes cleanup after cancellation during a reply", async () => {
    const abort = new AbortController();
    const normal = ppcFixture();
    const remote = await stub((command, peer) => {
      if (command === "p2") {
        abort.abort();
        setImmediate(() => {
          if (!peer.socket.destroyed) peer.reply("00000002");
        });
        return undefined;
      }
      return normal(command, peer);
    });
    const report = await observe(input(remote.endpoint), abort.signal);
    expect(report.completion).toBe("cancelled");
    expect(report.stops[0]!.registers.map((register) => register.name)).toEqual(
      ["r0", "r1"],
    );
    expect(report.cleanup.status).toBe("complete");
    expect(
      remote.peers[0]!.commands.filter((command) => command === "interrupt"),
    ).toHaveLength(1);
  });
  it("bounds idle tracing by the session deadline and interrupts before final halt", async () => {
    const normal = ppcFixture();
    const remote = await stub((command, peer) =>
      command === "c" ? undefined : normal(command, peer),
    );
    const report = await observe(
      input(remote.endpoint, { duration_ms: 150, max_stops: 5 }),
    );
    expect(report.completion).toBe("completed");
    expect(report.stops).toHaveLength(1);
    expect(report.cleanup.run_state).toBe("halted-observed");
    expect(remote.peers[0]!.commands.at(-1)).toBe("interrupt");
  });
  it("retains unresolved breakpoint ownership when the stub refuses removal", async () => {
    const remote = await stub(ppcFixture({ refuseRemoval: true }));
    const report = await observe(
      input(remote.endpoint, {
        breakpoint_scope: "exclusive-session",
        hooks: [{ label: "ipc", kind: "ipc", address: "0x80001000" }],
      }),
    );
    expect(report.cleanup.status).toBe("incomplete");
    expect(report.cleanup.remaining_breakpoints).toEqual(["0x80001000"]);
    expect(report.cleanup.reason).toContain("not acknowledged");
  });
  it("retains successfully read memory prefixes when a later bounded chunk fails", async () => {
    const normal = ppcFixture();
    let chunks = 0;
    const remote = await stub((command, peer) => {
      if (command === "p4") return "00000200";
      if (command.startsWith("m"))
        return ++chunks === 1 ? "ab".repeat(256) : "E01";
      return normal(command, peer);
    });
    const report = await observe(
      input(remote.endpoint, {
        max_stops: 2,
        breakpoint_scope: "exclusive-session",
        hooks: [
          {
            label: "send",
            kind: "network",
            address: "0x80001000",
            memory: [
              {
                label: "prefix",
                address_register: "r3",
                length_register: "r4",
                length: 512,
              },
            ],
          },
        ],
      }),
    );
    expect(report.completion).toBe("partial");
    expect(report.stops[1]!.memory[0]).toMatchObject({
      requested_bytes: "512",
      bytes: 256,
      truncated: true,
      content_base64: null,
      sha256: createHash("sha256")
        .update(Buffer.alloc(256, 0xab))
        .digest("hex"),
    });
    expect(report.stops[1]!.limitations[0]).toContain("incomplete");
    expect(report.cleanup.status).toBe("complete");
  });
  it("removes a possibly inserted breakpoint after its acknowledgment times out", async () => {
    const normal = ppcFixture();

    const remote = await stub((command, peer) => {
      if (command.startsWith("Z0")) {
        setTimeout(() => {
          if (!peer.socket.destroyed) peer.reply("OK");
        }, 30);
        return undefined;
      }
      return normal(command, peer);
    });
    const report = await observe(
      input(remote.endpoint, {
        command_timeout_ms: 20,
        breakpoint_scope: "exclusive-session",
        hooks: [{ label: "send", kind: "network", address: "0x80001000" }],
      }),
    );
    expect(report.completion).toBe("timeout");
    expect(report.cleanup).toMatchObject({
      status: "complete",
      remaining_breakpoints: [],
    });
    expect(remote.peers[0]!.commands).toContain("z0,80001000,4");
  });
});
describe("console debugger malformed boundaries (simulated stubs)", () => {
  it("retains stops and incomplete cleanup on malformed or oversized wire input", async () => {
    const normal = ppcFixture();
    const remote = await stub((command, peer) => {
      if (command === "p3") {
        peer.socket.write(`$${"0".repeat(70_000)}`);
        return undefined;
      }
      return normal(command, peer);
    });
    const report = await observe(input(remote.endpoint));
    expect(report.completion).toBe("partial");
    expect(report.failure).toContain("budget");
    expect(report.stops[0]!.registers).toHaveLength(3);
    expect(report.cleanup.status).toBe("incomplete");
  });
  it("rejects hook ownership and missing generic maps before opening a socket", async () => {
    const remote = await stub(ppcFixture());
    const adapter = new ConsoleDebuggerAdapter();
    const hook = await adapter.observe(
      input(remote.endpoint, {
        hooks: [{ label: "send", kind: "network", address: "0x80001000" }],
      }),
    );
    const map = await adapter.observe(
      input(remote.endpoint, { provider: "openocd" }),
    );
    expect(hook.ok).toBe(false);
    expect(map.ok).toBe(false);
    expect(remote.peers).toEqual([]);
  });
});
