# Console and game observation

Use the connected server's advertised contracts; an older installed server may not yet expose these tools.

1. Bind the console model/profile, processor, game region/revision and image digest. For overlay-based games, retain the active overlay and load address. A declared hash alone does not authenticate a live stub.
2. Ingest an explicit PCAP/PCAPNG with `inspect_console_network_capture`. Preserve file hashes, packet IDs, byte locations, stream gaps and unsupported/opaque traffic. Use existing HAR/mitmproxy inspection for those formats.
3. Use `observe_console_debugger` only for a selected emulator or established hardware GDB endpoint. `dolphin` owns its PPC register layout; generic/OpenOCD requires a verified register map. Select DS ARM9 and ARM7 separately. Retail hardware has no assumed debug interface.
4. Label exact code, IPC and socket hooks using verified symbol/address mappings. Sample only the buffers needed for the question. Hooks require an exclusive breakpoint session. Respect `resume_on_finish`; retain all partial evidence and incomplete cleanup details. Do not kill or reset an attached target.
5. Record player input timestamps and import reports with `correlate_console_observations`. Specify clock mappings and uncertainty, including debugger latency/pauses. Preserve source IDs; attach retained Evidence only to matching report contents. Never upgrade temporal coincidence or equal payloads into causal proof.
6. Recover framing, session rules, response formats and persistent state, then implement and test each actual player workflow. Reconnects, failed/duplicate requests, concurrent clients and restart recovery belong in acceptance tests. A packet trace alone cannot establish complete original server behavior.

For Pokémon Platinum GTS, separate connection/profile setup, deposit/commit, search, exchange/commit, retrieval and withdrawal. Source code and community replacements inform hypotheses; match them to the selected ROM revision and verify with client behavior. Real emulator tests do not establish DS Lite hardware compatibility.

CLI commands mirror tool names with hyphens and accept `--input` JSON or a file. The repository's `docs/console-observation.md` contains exact examples and protocol references.
