// MMA FILE SUMMARY
// Purpose: Tests correlation uncertainty, target separation and reconstruction coverage semantics.
// Responsibilities: Exercise cross-layer joins and failure/capacity cases through the public domain function.
// Invariants: No subprocesses or runtime targets; fixtures are synthetic reported evidence.
import { describe, expect, it } from "vitest";
import { correlateConsoleObservations } from "./consoleCorrelation.js";
import { consoleCorrelationSchema } from "./consoleObservation.js";

const sha = "a".repeat(64);
const event = (
  id: string,
  kind: "action" | "native" | "ipc" | "network",
  timestamp: string | null,
  extras: Record<string, unknown> = {},
) => ({
  event_id: id,
  session_id: "run",
  game_sha256: sha,
  kind,
  label: id,
  clock_id: "host",
  timestamp_ns: timestamp,
  source: { artifact_sha256: "b".repeat(64), locator: `/events/${id}` },
  ...extras,
});
const input = (events: unknown[], extras: Record<string, unknown> = {}) => ({
  target: {
    platform_id: "nintendo.nintendo_ds_family",
    profile_version: "0.1.1",
    game_build_id: "synthetic-platinum",
    game_sha256: sha,
  },
  session_id: "run",
  events,
  clocks: [
    {
      clock_id: "host",
      offset_ns: "0",
      uncertainty_ns: "10",
      evidence: "Synthetic shared clock",
    },
  ],
  window_ns: "100",
  client_addresses: ["192.0.2.2"],
  ...extras,
});
const report = (value: unknown) => {
  const result = correlateConsoleObservations(value);
  if (!result.ok) throw result.error;
  return consoleCorrelationSchema.parse(result.value);
};
const parent = (id: string) => ({
  event_id: id,
  basis: "producer-propagated-id",
  evidence: "Synthetic propagated trace identifier",
});

describe("console cross-layer correlation", () => {
  it("retains a forward candidate when clock uncertainty overlaps reversed medians", () => {
    const result = report(
      input([event("action", "action", "105"), event("call", "native", "100")]),
    );
    expect(result.edges).toEqual([
      expect.objectContaining({
        from: "action",
        to: "call",
        relationship: "temporal-candidate",
        confidence: "inferred",
      }),
    ]);
  });
  it("preserves a reported action/native/IPC/packet chain and derives unverified service requirements", () => {
    const payload = {
      sha256: "c".repeat(64),
      bytes: 32,
      complete: true,
      representation: "application-buffer",
    };
    const result = report(
      input([
        event("action", "action", "1000"),
        event("call", "native", "1010", {
          parent: parent("action"),
          code: { address: "0x02001000", symbol: "send", module_sha256: sha },
          payload,
        }),
        event("ipc", "ipc", "1020", {
          parent: parent("call"),
          ipc: {
            channel: "ARM9/ARM7",
            operation: "reported-fifo",
            request_id: "7",
          },
        }),
        event("packet", "network", "1030", {
          parent: parent("ipc"),
          payload: { ...payload, representation: "transport-segment" },
          flow: {
            transport: "tcp",
            source: { address: "192.0.2.2", port: 3000 },
            destination: { address: "192.0.2.8", port: 80 },
          },
        }),
      ]),
    );
    expect(
      result.edges.filter((edge) => edge.relationship === "reported-parent"),
    ).toHaveLength(3);
    expect(
      result.edges.some((edge) => edge.relationship === "same-payload"),
    ).toBe(true);
    expect(result.edges.every((edge) => !edge.causal_proof)).toBe(true);
    expect(result.backend_contract.services[0]?.outbound_event_ids).toEqual([
      "packet",
    ]);
    expect(
      result.backend_contract.scenarios[0]?.reported_chain_event_ids,
    ).toEqual(expect.arrayContaining(["call", "ipc", "packet"]));
    expect(result.backend_contract.fully_functional_replacement_verified).toBe(
      false,
    );
  });

  it("keeps missing clock mappings and parents unresolved without inventing timing links", () => {
    const result = report(
      input([
        event("action", "action", "1"),
        event("packet", "network", "2", {
          clock_id: "unmapped",
          parent: parent("missing"),
        }),
      ]),
    );
    expect(result.edges).toEqual([]);
    expect(result.unresolved).toHaveLength(2);
    expect(result.timeline[1]?.aligned_timestamp_ns).toBeNull();
  });

  it("retains exact clock alignment beyond safe JS integers and flags contradictory propagation", () => {
    const result = report(
      input(
        [
          event("parent", "action", "9007199254741999999"),
          event("child", "native", "9007199254740999999", {
            parent: parent("parent"),
          }),
        ],
        {
          clocks: [
            {
              clock_id: "host",
              offset_ns: "-123",
              uncertainty_ns: "0",
              evidence: "Synthetic anchor",
            },
          ],
        },
      ),
    );
    expect(result.timeline[0]?.aligned_timestamp_ns).toBe(
      "9007199254740999876",
    );
    expect(result.unresolved[0]?.reason).toContain("after child");
  });
});

describe("console correlation boundaries", () => {
  it.each([
    [event("dup", "action", "1"), event("dup", "native", "2")],
    [event("wrong-run", "action", "1", { session_id: "another-run" })],
    [event("wrong-build", "action", "1", { game_sha256: "d".repeat(64) })],
    [
      event("a", "action", "1", { parent: parent("b") }),
      event("b", "native", "2", { parent: parent("a") }),
    ],
  ])("rejects ambiguous identities and cyclic parents", (...events) => {
    expect(correlateConsoleObservations(input(events)).ok).toBe(false);
  });

  it("bounds returned links and marks remaining coverage unknown", () => {
    const result = report(
      input(
        [
          event("a", "action", "1"),
          event("n", "native", "2"),
          event("i", "ipc", "3"),
          event("p", "network", "4"),
        ],
        { max_edges: 1 },
      ),
    );
    expect(result.edges).toHaveLength(1);
    expect(result.coverage.complete).toBe(false);
    expect(result.coverage.truncation_reason).not.toBeNull();
  });

  it("does not equate partial or empty payloads and does not infer server direction", () => {
    const result = report(
      input([
        event("native", "native", null, {
          payload: {
            sha256: sha,
            bytes: 0,
            complete: true,
            representation: "application-buffer",
          },
        }),
        event("packet", "network", null, {
          payload: {
            sha256: sha,
            bytes: 0,
            complete: false,
            representation: "datagram",
          },
          flow: {
            transport: "udp",
            source: { address: "192.0.2.9", port: 1000 },
            destination: { address: "192.0.2.8", port: 53 },
          },
        }),
      ]),
    );
    expect(result.edges).toEqual([]);
    expect(result.backend_contract.services).toEqual([]);
  });
});
