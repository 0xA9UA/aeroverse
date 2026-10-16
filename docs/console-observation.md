# Console and game network observation

REA can ingest console packet captures, observe a selected GDB-compatible debug endpoint, and correlate the resulting evidence with player actions and IPC observations. The output includes a timeline, typed links and a backend requirements report.

| Tool                              | Input                                                              | Result                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `inspect_console_network_capture` | Local PCAP or PCAPNG                                               | Source digest, exact packet coordinates/timestamps, transport endpoints, payload digests, decoding and coverage limits |
| `observe_console_debugger`        | Explicit endpoint, platform/build identity, register map and hooks | Timestamped stops, guest registers, selected memory, partial failures and cleanup status                               |
| `correlate_console_observations`  | Actions, capture/debugger reports, clock mappings                  | Action → code → IPC → network candidates, source references and reconstruction requirements                            |

The CLI uses the same names with hyphens. Each accepts `--input` containing inline JSON or a JSON file. These tools work without opening a disassembler session. Static analysis remains available through REA's existing native tools: bind the extracted executable/overlay by digest, then resolve a captured address against that specific image and its actual load mapping.

## Ingest traffic

For Wireshark field discovery and selected-field queries, use [the TShark tools](packet-captures.md). For endpoint, DNS, TLS SNI and protocol summaries, use [the packet-summary tool](pcap-analysis.md). The console capture tool below provides built-in packet/message decoding and byte-source provenance for correlation without requiring TShark.

```sh
rea inspect-console-network-capture --input '{"capture_path":"/captures/platinum.pcapng"}' --json
```

Capture with an existing emulator capture facility, Wireshark/dumpcap, or a dedicated network capture point, then select the saved file. REA does not change system routing or begin privileged packet capture. A DS Lite's traffic can be collected at its access point; that alone does not expose its CPU state.

`include_payload: true` additionally returns packet payload hex. The default preserves digests and decoded metadata, including HTTP targets and DNS names. Original file identity, packet ordinals and offsets remain available. Message sources identify the exact packet byte ranges used. TCP assembly tracks direction, connection generation, gaps and conflicting retransmissions; selecting packet ordinals can leave a stream incomplete.

Plaintext HTTP/1.0 and HTTP/1.1 decoding exposes requests, responses, framing and body digests. UDP DNS decoding exposes questions and resource records. Unsupported framing, IP fragmentation, truncation, unknown link types and opaque encryption remain explicit. No TLS keys are inferred, and inspection does not replay packets or contact recorded endpoints. Use the existing HAR/mitmproxy inspection tool when the source is an application-level capture in those formats.

## Observe an emulator or hardware stub

Use an isolated runtime with an exclusive breakpoint owner. Supply the actual game digest, platform profile version, processor and emulator/firmware version. Those fields bind the investigation; a debug stub does not authenticate them.

```json
{
  "provider": "gdb-remote",
  "endpoint": { "transport": "tcp", "host": "127.0.0.1", "port": 3333 },
  "target": {
    "platform": "nintendo.nintendo_ds_family",
    "processor": "arm9",
    "profile": "0.1.1",
    "game_build_sha256": "REPLACE_WITH_64_LOWERCASE_HEX_DIGEST",
    "runtime_version": "melonDS 1.1"
  },
  "register_map": [
    { "name": "r0", "number": 0, "bits": 32, "byte_order": "little" },
    { "name": "r1", "number": 1, "bits": 32, "byte_order": "little" },
    { "name": "r2", "number": 2, "bits": 32, "byte_order": "little" },
    { "name": "r3", "number": 3, "bits": 32, "byte_order": "little" },
    { "name": "sp", "number": 13, "bits": 32, "byte_order": "little" },
    { "name": "lr", "number": 14, "bits": 32, "byte_order": "little" },
    { "name": "pc", "number": 15, "bits": 32, "byte_order": "little" },
    { "name": "cpsr", "number": 16, "bits": 32, "byte_order": "little" }
  ],
  "hooks": [],
  "duration_ms": 10000,
  "max_stops": 64,
  "resume_on_finish": true,
  "memory_policy": "hash"
}
```

Save the edited object as `debug.json`, then run:

```sh
rea observe-console-debugger --input debug.json --json > debug-evidence.json
```

With no hooks, this observes the initial halted context, then resumes for the selected interval. To trace calls, add hooks containing `label`, `kind` (`native`, `ipc`, `network`), an exact `address` and `instruction_size` (2 for Thumb, 4 for ARM/PPC), and set `breakpoint_scope` to `exclusive-session`. A hook can sample memory through `memory: [{"label":"send-buffer","address_register":"r0","offset":0,"length":4096,"length_register":"r1"}]`. The optional length register selects the actual size up to the declared cap; truncation is reported. Register choices must come from the function's actual ABI, not this illustrative example. `memory_policy: "bytes"` returns sampled bytes as well as their hash.

Hooks classify caller-selected addresses; they do not discover socket APIs or decode IPC automatically. Breakpoints pause and perturb timing. Repeated hits are stepped over explicitly, and the observer removes only its exclusively owned hooks. Every report preserves final run-state intent and incomplete cleanup. A cancelled call can return partial observations because discarding them would conceal target state changes.

| Runtime/interface         | Adapter boundary                                                                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| melonDS                   | Explicit ARM9/ARM7 endpoints with independent processor identities and little-endian register maps; requires a build with GDB stub enabled |
| Dolphin                   | `provider: dolphin` supplies its PPC register map; this does not expose an emulated IOS ARM processor or host-native thread trace          |
| Other emulators           | `gdb-remote` with a verified register map and compatible all-stop RSP commands; compatibility must be tested per build                     |
| Hardware GDB stub/OpenOCD | `gdb-remote`/`openocd` with an already configured target endpoint and explicit register map; board/debug access is established outside REA |
| Stock DS Lite             | No built-in retail GDB interface is assumed. Emulator validation and network capture do not prove on-device debugging support              |

The adapter uses GDB's remote wire protocol directly; a separate GDB executable is optional. An existing GDB debugger must release the endpoint before REA attaches. No flash programming, target reset, arbitrary monitor command, or target kill is performed.

## Correlate actions and traces

Create a correlation input with `target: {platform_id, profile_version, game_build_id, game_sha256}`, `session_id`, and these collections:

- `events`: action markers or producer-native IPC/code events. Each supplies an ID, kind, label, session/game digest, clock ID, integer nanosecond timestamp and exact source digest/locator. Action timestamps should come from the input event recorder; a label entered later is an analyst annotation.
- `network_captures`: `{clock_id, report, evidence_id?}` wrappers around capture Evidence's `normalized_result`. Packets and decoded messages become separate events; HTTP request targets and DNS question names remain visible. A message timestamp is the earliest source packet time, not the application call time.
- `debugger_observations`: equivalent wrappers around debugger reports. The importer checks their declared platform/profile/game identity, retains CPU identity and produces code/memory events.
- `clocks`: `{clock_id, offset_ns, uncertainty_ns, evidence}` measurements. Add offset to producer time to obtain session time. Host wall clocks, emulator cycles and hardware clocks require explicit alignment. Breakpoint pauses and synchronization error belong in uncertainty.
- `client_addresses`: addresses as seen in the capture, after any NAT, to distinguish outbound from inbound packets.

```sh
rea correlate-console-observations --input correlation.json --json > correlation-evidence.json
```

`reported-parent` retains producer-reported identifier propagation. `same-payload` reports equal complete nonempty bytes across layers. `temporal-candidate` considers clock uncertainty and the selected window. `analyst-hypothesis` retains a manual relationship. All preserve `causal_proof: false`: additional controlled experiments are needed to establish causation. Unknown clocks, missing parents, contradictions and capacity limits remain visible. Reusing a socket, endpoint pair or similar timestamp does not prove the same request.

Graph `coverage.complete` means the supplied event set was processed within its budgets, not that all game behavior was observed. Optional Evidence IDs become retained links only after verification; a digest or ID attached to unrelated content is not provenance.

## Reconstruct a backend

Use the derived service endpoints, observed HTTP requests, source events and action scenarios to recover response fields, authentication/session lifecycle and durable state. Decoded-message IDs are listed explicitly within the directed observations; responses are not paired by timing alone. Implement each scenario against an independent expected outcome, then exercise the real client with retries, disconnects, concurrent clients and server restarts. The generated report deliberately remains `requirements-only` until those tests exist; it does not generate a complete game server from request packets alone.

For the selected Pokémon Platinum GTS investigation, the initial scenarios are connect/profile setup, deposit/commit, search, exchange/commit, result retrieval and withdrawal. A faithful replacement also needs atomic exchange, duplicate-request handling, save/reconnect recovery and the game's error behavior. The upstream [client networking definitions](https://github.com/pret/pokeplatinum/blob/1dc13dcea40c04ab53f1f607de46023dc409ef20/include/gts_application/networking.h) and [client state machine](https://github.com/pret/pokeplatinum/blob/1dc13dcea40c04ab53f1f607de46023dc409ef20/src/gts_application/screens/network_handler.c) are useful source references; confirm their code mapping against the selected ROM revision before assigning hooks. Existing [Poké Classic Framework](https://github.com/mm201/pkmn-classic-framework/tree/9045841cae7e3a28bbc3caaa78e68a5e06e5868d) is a comparison implementation, not an oracle for every original server behavior.

The DS game's ARM9, ARM7 and loadable overlays are distinct code/address contexts. A GTS overlay address is meaningful only while the matching overlay is loaded. Hook application requests, socket buffers and FIFO/IPC boundaries separately, retain overlay and module digests, and compare captured requests with the player's selected action. [melonDS GDB implementation](https://github.com/melonDS-emu/melonDS/tree/1.1/src/debug) documents the transport; [the Platinum build guide](https://github.com/pret/pokeplatinum/blob/1dc13dcea40c04ab53f1f607de46023dc409ef20/INSTALL.md) describes its overlay-aware debugging setup.
