/** MMA FILE SUMMARY
 * Purpose: Supplies an explicitly simulated RSP peer for adapter and public CLI/MCP regressions.
 * Invariants: Local socket protocol coverage does not establish real console or emulator compatibility.
 */
import { createServer, type Socket } from "node:net";
import { onTestFinished } from "vitest";
import {
  observeConsoleDebuggerInputSchema,
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
function frame(payload: string): string {
  const checksum = [...Buffer.from(payload)].reduce(
    (sum, byte) => (sum + byte) & 255,
    0,
  );
  return `$${payload}#${checksum.toString(16).padStart(2, "0")}`;
}
export async function stub(
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
  onTestFinished(async () => {
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
export function input(
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
export function ppcFixture(
  options: {
    features?: string;
    read?: (command: string, peer: Peer) => string | undefined;
    refuseRemoval?: boolean;
    memory?: string;
  } = {},
) {
  let pc = 0x100;
  const memory = Buffer.from(options.memory ?? "ABCDEF");
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
              ? memory.length
              : number === 67
                ? 0x80003000
                : number
      )
        .toString(16)
        .padStart(8, "0");
    }
    if (/^m[0-9a-f]+,[0-9a-f]+$/.test(command))
      return memory
        .toString("hex")
        .slice(0, Number.parseInt(command.split(",")[1]!, 16) * 2);
    throw new Error(`Unmodeled fixture command: ${command}`);
  };
}
