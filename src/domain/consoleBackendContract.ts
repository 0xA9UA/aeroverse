// MMA FILE SUMMARY
// Purpose: Derives backend reconstruction requirements from a bounded correlation graph.
// Responsibilities: Group directed service traffic and action scenarios without inventing protocol semantics.
// Public interface: deriveConsoleBackendContract().
// Invariants: Requirements remain unverified; network traces alone cannot prove functional equivalence.
import type {
  ConsoleCorrelationEdge,
  ConsoleCorrelationInput,
  ConsoleCorrelationReport,
} from "./consoleObservation.js";

type Backend = ConsoleCorrelationReport["backend_contract"];

const collectServices = (
  input: ConsoleCorrelationInput,
): Backend["services"] => {
  const clients = new Set(input.client_addresses);
  const services = new Map<string, Backend["services"][number]>();
  for (const event of input.events) {
    const flow = event.flow;
    if (event.kind !== "network" || flow === undefined) continue;
    const outgoing = clients.has(flow.source.address);
    const incoming = clients.has(flow.destination.address);
    if (outgoing === incoming) continue;
    const endpoint = outgoing ? flow.destination : flow.source;
    const key = JSON.stringify([
      flow.transport,
      endpoint.address,
      endpoint.port,
    ]);
    const service = services.get(key) ?? {
      transport: flow.transport,
      endpoint,
      evidence_events: [],
      outbound_event_ids: [],
      inbound_event_ids: [],
      outbound_message_event_ids: [],
      inbound_message_event_ids: [],
      observed_http_requests: [],
      protocol_semantics: "unknown" as const,
    };
    service.evidence_events.push(event.event_id);
    const message = event.network_message;
    (outgoing ? service.outbound_event_ids : service.inbound_event_ids).push(
      event.event_id,
    );
    if (message !== undefined) {
      (outgoing
        ? service.outbound_message_event_ids
        : service.inbound_message_event_ids
      ).push(event.event_id);
      if (outgoing && message.protocol === "http" && message.kind === "request")
        service.observed_http_requests.push({
          event_id: event.event_id,
          method: message.method,
          target: message.target,
          status: message.status,
        });
    }
    services.set(key, service);
  }
  return [...services.values()];
};

const collectScenarios = (
  input: ConsoleCorrelationInput,
  edges: readonly ConsoleCorrelationEdge[],
): { scenarios: Backend["scenarios"]; complete: boolean } => {
  const adjacency = new Map<string, ConsoleCorrelationEdge[]>();
  for (const edge of edges) {
    const list = adjacency.get(edge.from) ?? [];
    list.push(edge);
    adjacency.set(edge.from, list);
  }
  let remaining = input.max_edges;
  let complete = true;
  const scenarios: Backend["scenarios"] = [];
  for (const action of input.events.filter(
    (event) => event.kind === "action",
  )) {
    const reported = new Set<string>();
    const candidates = new Set<string>();
    const visited = new Map<string, boolean>([[action.event_id, true]]);
    const queue = [{ id: action.event_id, propagated: true }];
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index];
      if (current === undefined) continue;
      for (const edge of adjacency.get(current.id) ?? []) {
        if (remaining <= 0) {
          complete = false;
          break;
        }
        remaining -= 1;
        if (edge.to === action.event_id) continue;
        const propagated =
          current.propagated && edge.relationship === "reported-parent";
        (propagated ? reported : candidates).add(edge.to);
        if (
          !visited.has(edge.to) ||
          (propagated && visited.get(edge.to) === false)
        ) {
          visited.set(edge.to, propagated);
          queue.push({ id: edge.to, propagated });
        }
      }
    }
    for (const id of reported) candidates.delete(id);
    scenarios.push({
      action_event_id: action.event_id,
      action: action.label,
      reported_chain_event_ids: [...reported],
      candidate_event_ids: [...candidates],
      requirements: [
        {
          id: `scenario-${scenarios.length + 1}`,
          description:
            "Reproduce the player-visible outcome from a fresh client session; compare response fields, state changes and failures with an independently recorded expected outcome.",
          status: "unverified",
          evidence_events: [action.event_id],
        },
      ],
    });
  }
  return { scenarios, complete };
};

export const deriveConsoleBackendContract = (
  input: ConsoleCorrelationInput,
  edges: readonly ConsoleCorrelationEdge[],
): { contract: Backend; complete: boolean } => {
  const { scenarios, complete } = collectScenarios(input, edges);
  const obligations = [
    [
      "framing",
      "Recover application message framing, field types, encoding, sequencing, error codes and request/response pairing; TCP packet boundaries are not message boundaries.",
    ],
    [
      "identity",
      "Implement the client identity, authentication/session lifecycle, transport security and routing that the selected game build actually requires.",
    ],
    [
      "state",
      "Specify persistent domain state, atomic transactions, retries, idempotency, concurrent clients and restart recovery.",
    ],
    [
      "compatibility",
      "Verify each required player workflow on the selected build and target model, including disconnects, timeouts and invalid requests.",
    ],
    [
      "oracle",
      "Record independent expected outcomes and compare a complete client-to-replacement-server session; observed requests alone cannot establish original response behavior.",
    ],
  ];
  return {
    complete,
    contract: {
      readiness: "requirements-only",
      fully_functional_replacement_verified: false,
      services: collectServices(input),
      scenarios,
      requirements: obligations.map(([id, description]) => ({
        id: id ?? "unknown",
        description: description ?? "Unknown requirement",
        status: "unverified",
        evidence_events: [],
      })),
    },
  };
};
