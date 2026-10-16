/** MMA FILE SUMMARY
 * Purpose: Owns one bounded GDB Remote Serial Protocol socket and packet stream.
 * Responsibilities: Fragmented framing, wire checksums, acknowledgments, escaping, deadlines and cancellation.
 * Public interface: RspConnection.open(), request(), send(), interrupt(), packet(), close().
 * Invariants: One sequential command owner; never launches, resets or kills a target.
 */
import { createConnection, type Socket } from "node:net";
import { performance } from "node:perf_hooks";
import type { ObserveConsoleDebuggerInput } from "../../domain/consoleDebugger.js";
import { CONSOLE_DEBUGGER_LIMITS } from "../../domain/consoleDebugger.js";

export class RspFailure extends Error {
  constructor(
    readonly kind: "timeout" | "cancelled" | "protocol" | "transport",
    message: string,
  ) {
    super(message);
  }
}
type Waiter = {
  resolve: (packet: string) => void;
  reject: (error: Error) => void;
  cleanup: () => void;
};
function parseFrame(
  buffer: Buffer,
): { payload: Buffer; consumed: number; validChecksum: boolean } | null {
  if (buffer[0] !== 36)
    throw new RspFailure(
      "protocol",
      "Unexpected debugger wire byte (non-stop notifications are not negotiated).",
    );
  let end = -1;
  for (let index = 1; index < buffer.length; index++) {
    if (buffer[index] === 125) {
      index++;
      continue;
    }
    if (buffer[index] === 35) {
      end = index;
      break;
    }
  }
  if (end < 0) {
    if (buffer.length > CONSOLE_DEBUGGER_LIMITS.packet_bytes + 4)
      throw new RspFailure(
        "protocol",
        "Debugger packet exceeds its allocation budget.",
      );
    return null;
  }
  if (end > CONSOLE_DEBUGGER_LIMITS.packet_bytes + 1)
    throw new RspFailure(
      "protocol",
      "Debugger packet exceeds its allocation budget.",
    );
  if (buffer.length < end + 3) return null;
  const payload = buffer.subarray(1, end);
  const checksum = buffer.subarray(end + 1, end + 3).toString("latin1");
  let sum = 0;
  for (const byte of payload) sum = (sum + byte) & 255;
  return {
    payload,
    consumed: end + 3,
    validChecksum:
      /^[0-9a-fA-F]{2}$/.test(checksum) &&
      Number.parseInt(checksum, 16) === sum,
  };
}
function decodePacket(payload: Buffer): string {
  const decoded: number[] = [];
  for (let index = 0; index < payload.length; index++) {
    const byte = payload[index]!;
    if (byte === 125) {
      const escaped = payload[++index];
      if (escaped === undefined)
        throw new RspFailure("protocol", "Truncated debugger escape.");
      decoded.push(escaped ^ 32);
    } else if (byte === 42) {
      const count = payload[++index];
      const previous = decoded.at(-1);
      if (
        count === undefined ||
        previous === undefined ||
        count < 32 ||
        decoded.length + count - 29 > CONSOLE_DEBUGGER_LIMITS.packet_bytes
      )
        throw new RspFailure(
          "protocol",
          "Invalid or oversized debugger run-length encoding.",
        );
      for (let repeat = 0; repeat < count - 29; repeat++)
        decoded.push(previous);
    } else decoded.push(byte);
  }
  if (decoded.some((byte) => byte > 127))
    throw new RspFailure(
      "protocol",
      "Non-ASCII debugger response is unsupported by the observation command set.",
    );
  return Buffer.from(decoded).toString("ascii");
}
/** Frame bytes are checked before unescaping or expansion; malformed peers cannot grow the buffer indefinitely. */
export class RspConnection {
  #buffer: Buffer = Buffer.alloc(0);
  #packets: string[] = [];
  #waiter: Waiter | undefined;
  #failure: Error | undefined;
  #lastFrame: Buffer | undefined;
  #retries = 0;
  #badChecksums = 0;
  #noAck = false;
  constructor(readonly socket: Socket) {
    // RSP acknowledgments and their following command are separate small writes.
    socket.setNoDelay(true);
    socket.on("data", (data: Buffer) => this.#consume(data));
    socket.on("error", (error) =>
      this.#fail(new RspFailure("transport", error.message)),
    );
    socket.on("close", () =>
      this.#fail(new RspFailure("transport", "Debugger socket closed.")),
    );
  }
  static async open(
    endpoint: ObserveConsoleDebuggerInput["endpoint"],
    deadline: number,
    signal?: AbortSignal,
  ): Promise<RspConnection> {
    if (signal?.aborted)
      throw new RspFailure("cancelled", "Debugger attachment cancelled.");
    const socket =
      endpoint.transport === "tcp"
        ? createConnection({ host: endpoint.host, port: endpoint.port })
        : createConnection({ path: endpoint.path });
    const connection = new RspConnection(socket);
    try {
      await new Promise<void>((resolve, reject) => {
        const clear = () => {
          clearTimeout(timer);
          socket.off("connect", ready);
          socket.off("error", failed);
          signal?.removeEventListener("abort", abort);
        };
        const ready = () => {
          clear();
          resolve();
        };
        const failed = (error: Error) => {
          clear();
          reject(error);
        };
        const abort = () => {
          clear();
          reject(new RspFailure("cancelled", "Debugger attachment cancelled."));
        };
        const timer = setTimeout(
          () => {
            clear();
            reject(
              new RspFailure(
                "timeout",
                "Debugger connection deadline exceeded.",
              ),
            );
          },
          Math.max(1, Math.ceil(deadline - performance.now())),
        );
        socket.once("connect", ready);
        socket.once("error", failed);
        signal?.addEventListener("abort", abort, { once: true });
      });
      // GDB starts an all-stop connection with '+'. melonDS 1.1 explicitly consumes this before packet parsing.
      // https://github.com/melonDS-emu/melonDS/blob/1.1/src/debug/GdbStub.cpp#L291-L304
      socket.write("+");
      return connection;
    } catch (error) {
      connection.close();
      throw error;
    }
  }
  setNoAck(): void {
    this.#noAck = true;
  }
  send(command: string): void {
    if (this.#failure) throw this.#failure;
    const payload = Buffer.from(command, "ascii");
    if (payload.length > CONSOLE_DEBUGGER_LIMITS.packet_bytes)
      throw new RspFailure(
        "protocol",
        "Debugger command exceeds packet budget.",
      );
    let sum = 0;
    for (const byte of payload) sum = (sum + byte) & 255;
    const frame = Buffer.from(
      `$${command}#${sum.toString(16).padStart(2, "0")}`,
      "ascii",
    );
    this.#lastFrame = frame;
    this.#retries = 0;
    this.socket.write(frame);
  }
  interrupt(): void {
    if (this.#failure) throw this.#failure;
    this.socket.write(Buffer.from([3]));
  }
  async request(
    command: string,
    deadline: number,
    signal?: AbortSignal,
  ): Promise<string> {
    if (signal?.aborted)
      throw new RspFailure("cancelled", "Debugger observation cancelled.");
    if (performance.now() >= deadline)
      throw new RspFailure("timeout", "Debugger response deadline exceeded.");
    this.send(command);
    return this.packet(deadline, signal);
  }
  packet(deadline: number, signal?: AbortSignal): Promise<string> {
    if (signal?.aborted)
      return Promise.reject(
        new RspFailure("cancelled", "Debugger observation cancelled."),
      );
    if (performance.now() >= deadline)
      return Promise.reject(
        new RspFailure("timeout", "Debugger response deadline exceeded."),
      );
    const packet = this.#packets.shift();
    if (packet !== undefined) return Promise.resolve(packet);
    if (this.#failure) return Promise.reject(this.#failure);
    if (this.#waiter)
      return Promise.reject(
        new RspFailure(
          "protocol",
          "Concurrent debugger packet readers are unsupported.",
        ),
      );
    return new Promise((resolve, reject) => {
      const abort = () =>
        finish(new RspFailure("cancelled", "Debugger observation cancelled."));
      const finish = (error: Error) => {
        const waiter = this.#waiter;
        this.#waiter = undefined;
        waiter?.cleanup();
        reject(error);
      };
      const timer = setTimeout(
        () =>
          finish(
            new RspFailure("timeout", "Debugger response deadline exceeded."),
          ),
        Math.max(1, Math.ceil(deadline - performance.now())),
      );
      this.#waiter = {
        resolve,
        reject,
        cleanup: () => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", abort);
        },
      };
      signal?.addEventListener("abort", abort, { once: true });
    });
  }
  close(): void {
    this.socket.destroy();
  }
  #fail(error: Error): void {
    this.#failure ??= error;
    const waiter = this.#waiter;
    this.#waiter = undefined;
    waiter?.cleanup();
    waiter?.reject(this.#failure);
  }
  #deliver(packet: string): void {
    if (this.#waiter) {
      const waiter = this.#waiter;
      this.#waiter = undefined;
      waiter.cleanup();
      waiter.resolve(packet);
    } else if (this.#packets.length < 64) this.#packets.push(packet);
    else {
      this.#fail(
        new RspFailure(
          "protocol",
          "Unconsumed debugger packets exceeded the queue budget.",
        ),
      );
      this.close();
    }
  }
  #consume(data: Buffer): void {
    if (this.#failure) return;
    if (
      this.#buffer.length + data.length >
      2 * CONSOLE_DEBUGGER_LIMITS.packet_bytes + 16
    ) {
      this.#fail(
        new RspFailure("protocol", "Debugger input exceeds framing budget."),
      );
      this.close();
      return;
    }
    this.#buffer = Buffer.concat([this.#buffer, data]);
    try {
      while (this.#buffer.length > 0) {
        const first = this.#buffer[0];
        if (first === 43 || first === 45) {
          this.#buffer = this.#buffer.subarray(1);
          if (first === 43) this.#lastFrame = undefined;
          else if (!this.#noAck && this.#lastFrame && ++this.#retries <= 3)
            this.socket.write(this.#lastFrame);
          else
            throw new RspFailure(
              "protocol",
              "Unexpected or repeated debugger negative acknowledgment.",
            );
          continue;
        }
        const frame = parseFrame(this.#buffer);
        if (frame === null) return;
        const { payload } = frame;
        this.#buffer = this.#buffer.subarray(frame.consumed);
        if (!frame.validChecksum) {
          if (this.#noAck || ++this.#badChecksums > 3)
            throw new RspFailure(
              "protocol",
              "Debugger packet checksum is invalid.",
            );
          this.socket.write("-");
          continue;
        }
        if (!this.#noAck) this.socket.write("+");
        this.#badChecksums = 0;
        this.#deliver(decodePacket(payload));
      }
    } catch (error) {
      this.#fail(
        error instanceof Error
          ? error
          : new RspFailure("protocol", "Malformed debugger frame."),
      );
      this.close();
    }
  }
}
