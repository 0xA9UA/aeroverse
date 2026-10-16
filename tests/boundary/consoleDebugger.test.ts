/** MMA FILE SUMMARY
 * Purpose: Exercises debugger observation across a real local socket with controlled RSP peers.
 * Responsibilities: Framing, CPU register interpretation, repeated stops, bounded capture and lifecycle failures.
 * Invariants: Simulated stub behavior establishes protocol handling, not console/emulator/hardware support.
 */
import { createHash } from "node:crypto";
import { createServer, type Socket } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConsoleDebuggerAdapter,
  MELONDS_ARM_REGISTERS,
} from "../../src/console/debugger/ConsoleDebuggerAdapter.js";
import {
  observeConsoleDebuggerInputSchema,
  consoleDebuggerObservationSchema,
  type ObserveConsoleDebuggerInput,
} from "../../src/domain/consoleDebugger.js";

type Peer = {
  socket: Socket;
  commands: string[];
  acknowledgments: string[];
  noAck: boolean;
  reply: (
    payload: string,
    options?: { fragmented?: boolean; badChecksum?: boolean },
  ) => void;
};
const releases: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const release of releases.splice(0).reverse()) await release();
});
function frame(payload: string): string {
  const checksum = [...Buffer.from(payload)].reduce(
    (sum, byte) => (sum + byte) & 255,
    0,
  );
  return `$${payload}#${checksum.toString(16).padStart(2, "0")}`;
}
async function stub(
  handler: (command: string, peer: Peer) => string | undefined,
): Promise<{
  endpoint: ObserveConsoleDebuggerInput["endpoint"];
  peers: Peer[];
}> {
  const peers: Peer[] = [];
  const server = createServer((socket) => {
    socket.setNoDelay(true);
    let buffered = "";
    let resend: string | undefined;
    const peer: Peer = {
      socket,
      commands: [],
      acknowledgments: [],
      noAck: false,
      reply(payload, options) {
        const valid = frame(payload);
        resend = valid;
        const response = options?.badChecksum
          ? `${valid.slice(0, -2)}zz`
          : valid;
        if (options?.fragmented) {
          socket.write(response.slice(0, 2));
          setImmediate(() => {
            if (!socket.destroyed) socket.write(response.slice(2));
          });
        } else socket.write(response);
      },
    };
    peers.push(peer);
    socket.on("error", () => {
      /* A simulated transport failure is asserted through the adapter result. */
    });
    socket.on("data", (bytes) => {
      buffered += bytes.toString("ascii");
      while (buffered.length > 0) {
        const first = buffered[0];
        if (first === "+" || first === "-") {
          peer.acknowledgments.push(first);
          buffered = buffered.slice(1);
          if (first === "-" && resend !== undefined) socket.write(resend);
          continue;
        }
        if (first === "\u0003") {
          buffered = buffered.slice(1);
          peer.commands.push("interrupt");
          const response = handler("interrupt", peer);
          if (response !== undefined) peer.reply(response);
          continue;
        }
        if (first !== "$")
          throw new Error(`Unexpected client wire prefix ${String(first)}.`);
        const end = buffered.indexOf("#");
        if (end < 0 || buffered.length < end + 3) break;
        const command = buffered.slice(1, end);
        const wire = buffered.slice(0, end + 3);
        buffered = buffered.slice(end + 3);
        if (wire !== frame(command))
          throw new Error("Client sent an invalid checksum.");
        if (!peer.noAck) socket.write("+");
        peer.commands.push(command);
        const response = handler(command, peer);
        if (response !== undefined) peer.reply(response);
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  releases.push(async () => {
    for (const peer of peers) peer.socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Expected TCP listener.");
  return {
    endpoint: { transport: "tcp", host: "127.0.0.1", port: address.port },
    peers,
  };
}
function input(
  endpoint: ObserveConsoleDebuggerInput["endpoint"],
  overrides: Record<string, unknown> = {},
): ObserveConsoleDebuggerInput {
  return observeConsoleDebuggerInputSchema.parse({
    provider: "dolphin",
    endpoint,
    target: {
      platform: "nintendo.wii",
      processor: "powerpc",
      profile: "0.1.1",
      game_build_sha256: "a".repeat(64),
      runtime_version: "simulated-rsp-peer",
    },
    duration_ms: 1000,
    command_timeout_ms: 200,
    cleanup_timeout_ms: 200,
    max_stops: 1,
    resume_on_finish: false,
    ...overrides,
  });
}
function ppcFixture(
  options: {
    features?: string;
    read?: (command: string, peer: Peer) => string | undefined;
    refuseRemoval?: boolean;
  } = {},
) {
  let pc = 0x100;
  return (command: string, peer: Peer): string | undefined => {
    if (command === "qSupported:")
      return options.features ?? "swbreak+;hwbreak+";
    if (command === "qHostInfo") return "endian:big;ptrsize:4;";
    if (command === "interrupt" || command === "?") return "T0540:00000100;";
    if (command === "c") {
      pc = 0x80001000;
      return "T0540:80001000;";
    }
    if (command === "s") {
      pc += 4;
      return "T05";
    }
    if (/^Z0,[0-9a-f]+,[24]$/.test(command)) return "OK";
    if (/^z0,[0-9a-f]+,[24]$/.test(command))
      return options.refuseRemoval ? "E01" : "OK";
    if (/^p[0-9a-f]+$/.test(command)) {
      if (options.read) return options.read(command, peer);
      const number = Number.parseInt(command.slice(1), 16);
      return (
        number === 64
          ? pc
          : number === 3
            ? 0x80002000
            : number === 4
              ? 6
              : number === 67
                ? 0x80003000
                : number
      )
        .toString(16)
        .padStart(8, "0");
    }
    if (/^m[0-9a-f]+,[0-9a-f]+$/.test(command))
      return "414243444546".slice(
        0,
        Number.parseInt(command.split(",")[1]!, 16) * 2,
      );
    throw new Error(`Unmodeled fixture command: ${command}`);
  };
}
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
