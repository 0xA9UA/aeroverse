// MMA FILE SUMMARY
// Purpose: Names built-in console evidence producers without loading their implementations.
// Public interface: Capture, debugger and correlation provider identities.
// Invariants: Versions identify REA's adapters, not caller-declared console firmware or emulator versions.
export const CONSOLE_CAPTURE_PROVIDER_IDENTITY = Object.freeze({
  id: "rea-native-pcap",
  name: "REA console packet capture decoder",
  version: "1",
});

export const CONSOLE_DEBUGGER_PROVIDER_IDENTITY = Object.freeze({
  id: "rea-console-rsp",
  name: "REA console debugger observation provider",
  version: "1",
});

export const CONSOLE_CORRELATION_PROVIDER_IDENTITY = Object.freeze({
  id: "rea-console-correlation",
  name: "REA console observation correlation",
  version: "1",
});
