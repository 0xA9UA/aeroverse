# MMA_SKILL_INDEX

REA exposes local reverse engineering through a shared application layer and CLI/MCP transports. This index maps ownership; detailed provider behavior lives in the linked guides.

## Architecture

`domain + contracts ← application ports/workflows ← composition + provider adapters ← CLI/MCP`

| Module                                                                 | Owns                                                                             | Main boundary                                       |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------- |
| `src/domain/`, `src/contracts/`                                        | Validated input/output semantics, Evidence, capability and effect contracts      | Schemas and pure transformations                    |
| `src/application/`                                                     | Shared workflows, session routing and retained evidence                          | Services and provider ports                         |
| `src/composition/`                                                     | Provider construction and dependency wiring                                      | Factories consumed by transports                    |
| `src/cli.ts`, `src/cli/`                                               | One-shot commands and JSON input                                                 | `createCli()`                                       |
| `src/main/`, `src/server/`                                             | MCP lifecycle, named contract registration, Evidence retention                   | `createServer()`                                    |
| `src/{ghidra,hopper,ida,artifacts,native,dotnet,android,browser,...}/` | Engine/format-specific analysis                                                  | Provider ports implemented outside domain semantics |
| `src/process/`, `src/filesystem/`                                      | Owned process lifetime, bounded IO and cleanup                                   | Shared supervision/acquisition primitives           |
| `src/console/network/`                                                 | PCAP/PCAPNG containers and packet/message interpretation                         | `ConsoleNetworkCaptureAdapter.inspect()`            |
| `src/console/debugger/`                                                | GDB remote protocol, scoped live stops, registers, memory and breakpoint cleanup | `ConsoleDebuggerAdapter.observe()`                  |
| `src/domain/consoleObservation*.ts`                                    | Canonical action/code/IPC/network events and source import                       | Correlation schemas and report normalization        |
| `src/domain/consoleCorrelation.ts`, `consoleBackendContract.ts`        | Clock-aware graph candidates and backend requirements                            | `correlateConsoleObservations()`                    |
| `src/application/ConsoleObservationService.ts`                         | Common validation and Evidence for all console tools                             | `execute()` through capture/debugger ports          |

## Key flows

- `scripts/rea.mjs` selects CLI or MCP; both resolve named contracts and use the same application services.
- Console capture: stable artifact snapshot → container/packet decoding → bounded TCP assembly and HTTP/DNS interpretation → source-bound report → Evidence.
- Console live debugging: explicit endpoint + declared target → RSP negotiation → owned hooks/stops/memory → cleanup receipt → Evidence.
- Console reconstruction: action records + packet/message/debugger reports + measured clock mappings → typed candidate graph → service/scenario requirements. `consoleNetworkMessageEvents.ts` projects message metadata while retaining exact report pointers.
- Existing native analysis: explicit target → provider registry/session router → analysis workflow → Evidence ledger/export.

## Global invariants

- Keep observed, derived, inferred and unknown facts distinct. A declared game hash is not measured runtime identity.
- Retained Evidence and raw source identity survive both transports. Never attach unrelated Evidence references to a report.
- Domain semantics do not import transport, composition or provider implementations.
- Processes require established ownership before cleanup. Console attachment owns its socket and explicitly exclusive hooks, not the emulator or hardware.
- Console timing/payload matches are candidates, not causal proof. Packet inspection does not replay traffic. Backend requirements do not establish functional equivalence.
- Handwritten source changes carry current MMA file summaries; generated, binary, vendor and JSON files are exempt.

## Navigation

For a new public tool, start with `docs/tool-design.md`, its contract, application owner, then transport wiring. For console work, start with [the console guide](docs/console-observation.md). For tests and provider claims, use `docs/testing.md`; fake transports cannot establish hardware compatibility. Update this index when module ownership or public boundaries change.
