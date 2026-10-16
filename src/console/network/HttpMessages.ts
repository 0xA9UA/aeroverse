// MMA FILE SUMMARY
// Purpose: Interprets strictly framed plaintext HTTP/1.x within a retained contiguous TCP chunk.
// Public interface: decodeHttpMessages() returns complete or explicitly limited wire messages.
// Collaborators: RFC 9112 framing, console message schema and TCP-owned chunk boundaries.
// Invariants: No scanning across gaps, transfer decoding or request/response pairing; known credential headers are excluded.
import { createHash } from "node:crypto";
import {
  CONSOLE_MESSAGE_LIMITS,
  type ConsoleHttpMessage,
} from "../../domain/consoleNetworkMessages.js";

export interface ParsedHttpMessage {
  offset: number;
  bytes: number;
  wire_sha256: string;
  status: ConsoleHttpMessage["status"];
  http: ConsoleHttpMessage["http"];
  limitations: string[];
}
type Start = Pick<
  ConsoleHttpMessage["http"],
  "kind" | "version" | "method" | "target" | "status_code"
>;
type Header = ConsoleHttpMessage["http"]["headers"][number];
const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");
const credentialHeaders = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
]);
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;

/** Only a recognizable first message at a chunk boundary is interpreted; arbitrary payloads remain unknown. */
export const decodeHttpMessages = (
  bytes: Buffer,
  finAtChunkEnd: boolean,
): ParsedHttpMessage[] => {
  const messages: ParsedHttpMessage[] = [];
  let cursor = 0;
  while (
    cursor < bytes.length &&
    messages.length < CONSOLE_MESSAGE_LIMITS.messages
  ) {
    const end = bytes.indexOf("\r\n", cursor);
    const firstLine = bytes
      .subarray(
        cursor,
        end < 0
          ? Math.min(bytes.length, cursor + CONSOLE_MESSAGE_LIMITS.headerBytes)
          : Math.min(end, cursor + CONSOLE_MESSAGE_LIMITS.headerBytes),
      )
      .toString("latin1");
    const start = startLine(firstLine);
    if (start === null) break;
    const message = decodeMessage(bytes.subarray(cursor), start, finAtChunkEnd);
    messages.push({ ...message, offset: cursor });
    if (message.status !== "complete" || message.bytes === 0) break;
    cursor += message.bytes;
  }
  return messages;
};

const startLine = (line: string): Start | null => {
  const request = /^([^ ]+) ([^ ]+) (HTTP\/1\.[01])$/u.exec(line);
  if (request !== null && token.test(request[1]!) && visibleTarget(request[2]!))
    return {
      kind: "request",
      version: request[3] as Start["version"],
      method: request[1]!,
      target: safeUrl(request[2]!),
      status_code: null,
    };
  const response =
    /^(HTTP\/1\.[01]) ([1-9][0-9]{2})(?: [\t\x20-\x7e\x80-\xff]*)?$/u.exec(
      line,
    );
  return response === null
    ? null
    : {
        kind: "response",
        version: response[1] as Start["version"],
        method: null,
        target: null,
        status_code: Number(response[2]),
      };
};

const safeUrl = (value: string): string =>
  value.replace(/^((?:[a-z][a-z0-9+.-]*:)?\/\/)[^/?#]*@/iu, "$1");
const visibleTarget = (value: string): boolean => {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 32 || code >= 127) return false;
  }
  return true;
};
const validFieldValue = (value: string): boolean => {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if ((code < 32 && code !== 9) || code === 127) return false;
  }
  return true;
};
const responseHasNoBody = (start: Start): boolean =>
  start.kind === "response" &&
  ((start.status_code! >= 100 && start.status_code! < 200) ||
    [204, 304].includes(start.status_code!));
const emptyBody = (): ConsoleHttpMessage["http"]["body"] => ({
  bytes: 0,
  sha256: sha256(Buffer.alloc(0)),
  complete: false,
  representation: "transfer-payload",
});

const decodeMessage = (
  bytes: Buffer,
  start: Start,
  finAtEnd: boolean,
): Omit<ParsedHttpMessage, "offset"> => {
  const headerEnd = bytes.indexOf("\r\n\r\n");
  const http: ConsoleHttpMessage["http"] = {
    ...start,
    headers: [],
    framing: "unknown",
    body: emptyBody(),
  };
  const limitations = [
    "HTTP message interpretation does not establish request/response pairing, application field semantics, HEAD/CONNECT context, server equivalence or successful delivery.",
    "Known transport credential headers and URL userinfo are excluded from interpreted fields; packet payload release is separately controlled.",
  ];
  const finish = (
    status: ParsedHttpMessage["status"],
    length: number,
    reason?: string,
  ): Omit<ParsedHttpMessage, "offset"> => ({
    bytes: length,
    wire_sha256: sha256(bytes.subarray(0, length)),
    status,
    http,
    limitations: reason === undefined ? limitations : [...limitations, reason],
  });
  if (headerEnd < 0 || headerEnd > CONSOLE_MESSAGE_LIMITS.headerBytes)
    return finish(
      headerEnd < 0 && bytes.length <= CONSOLE_MESSAGE_LIMITS.headerBytes
        ? "incomplete"
        : "unsupported",
      bytes.length,
      "HTTP header terminator is absent from the retained header budget; no complete message is established.",
    );
  const parsedHeaders = parseHeaders(
    bytes.subarray(0, headerEnd).toString("latin1"),
  );
  if (parsedHeaders === null)
    return finish(
      "invalid",
      headerEnd + 4,
      "Invalid or obsolete-folded HTTP field syntax prevents trustworthy framing.",
    );
  http.headers = parsedHeaders.projected;
  const bodyStart = headerEnd + 4;
  const body = bytes.subarray(bodyStart);
  const lengthFields = parsedHeaders.raw.get("content-length") ?? [];
  const transferFields = parsedHeaders.raw.get("transfer-encoding") ?? [];
  if (transferFields.length > 0) {
    http.framing = "unsupported";
    return finish(
      lengthFields.length > 0 ? "invalid" : "unsupported",
      bytes.length,
      "Transfer coding (including chunked) is outside this decoder; simultaneous Transfer-Encoding and Content-Length is ambiguous and rejected.",
    );
  }
  if (responseHasNoBody(start)) {
    http.framing = "no-body";
    http.body.complete = true;
    return finish("complete", bodyStart);
  }
  if (lengthFields.length > 1 || lengthFields[0]?.includes(",")) {
    http.framing = "unsupported";
    return finish(
      "unsupported",
      bytes.length,
      "Repeated/list Content-Length fields are not normalized; message framing remains unverified.",
    );
  }
  if (lengthFields.length === 1)
    return contentLengthBody({
      http,
      body,
      bodyStart,
      declared: lengthFields[0]!,
      finish,
    });
  if (start.kind === "request") {
    http.framing = "no-body";
    http.body.complete = true;
    return finish("complete", bodyStart);
  }
  http.framing = "close-delimited";
  http.body = {
    bytes: body.length,
    sha256: sha256(body),
    complete: finAtEnd,
    representation: "transfer-payload",
  };
  return finish(
    finAtEnd ? "complete" : "incomplete",
    bytes.length,
    finAtEnd
      ? undefined
      : "No length field or contiguous graceful FIN establishes the end of this response body.",
  );
};

const contentLengthBody = ({
  http,
  body,
  bodyStart,
  declared,
  finish,
}: {
  http: ConsoleHttpMessage["http"];
  body: Buffer;
  bodyStart: number;
  declared: string;
  finish: (
    status: ParsedHttpMessage["status"],
    length: number,
    reason?: string,
  ) => Omit<ParsedHttpMessage, "offset">;
}): Omit<ParsedHttpMessage, "offset"> => {
  http.framing = "content-length";
  if (!/^[0-9]+$/u.test(declared))
    return finish(
      "invalid",
      bodyStart,
      "Content-Length is not a supported nonnegative decimal length.",
    );
  const expected = BigInt(declared);
  const retained =
    expected > BigInt(body.length) ? body.length : Number(expected);
  const complete = expected <= BigInt(body.length);
  http.body = {
    bytes: retained,
    sha256: sha256(body.subarray(0, retained)),
    complete,
    representation: "transfer-payload",
  };
  return finish(
    complete ? "complete" : "incomplete",
    bodyStart + retained,
    complete
      ? undefined
      : "Retained contiguous bytes do not cover the declared HTTP body length.",
  );
};

const parseHeaders = (
  block: string,
): { projected: Header[]; raw: Map<string, string[]> } | null => {
  const projected: Header[] = [],
    raw = new Map<string, string[]>();
  for (const line of block.split("\r\n").slice(1)) {
    const colon = line.indexOf(":");
    if (colon <= 0 || !token.test(line.slice(0, colon))) return null;
    const name = line.slice(0, colon),
      lower = name.toLowerCase();
    const value = line.slice(colon + 1).replace(/^[\t ]+|[\t ]+$/gu, "");
    if (!validFieldValue(value)) return null;
    const values = raw.get(lower) ?? [];
    values.push(value);
    raw.set(lower, values);
    const excluded = credentialHeaders.has(lower);
    const safe = ["location", "referer", "origin"].includes(lower)
      ? safeUrl(value)
      : value;
    projected.push({
      name,
      value: excluded ? null : safe,
      redacted: excluded || safe !== value,
    });
  }
  return { projected, raw };
};
