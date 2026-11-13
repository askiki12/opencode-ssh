import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";

/** Generate a short, readable identifier such as `ssh_1a2b3c4d5e6f`. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(6).toString("hex")}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Expand a leading `~` and return an absolute path.
 * Relative paths are resolved against the process working directory.
 */
export function expandPath(value: string): string {
  let result = value.trim();
  if (result === "~") return homedir();
  if (result.startsWith("~/") || result.startsWith("~\\")) {
    result = path.join(homedir(), result.slice(2));
  }
  result = result.replace(
    /%([^%]+)%/g,
    (match, name: string) => process.env[name] ?? match,
  );
  return path.resolve(result);
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(errorMessage(error));
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MAX_LINE_CHARS = 16 * 1024;

type EscapeState =
  | "normal"
  | "escape"
  | "csi"
  | "osc"
  | "osc-escape"
  | "string"
  | "string-escape"
  | "charset";

/**
 * Removes terminal control sequences and collapses carriage-return / backspace
 * edits. It is a small state machine so escape sequences split across chunks
 * are handled correctly, and it never buffers more than one bounded line.
 */
class TerminalSanitizer {
  private readonly decoder = new StringDecoder("utf8");
  private state: EscapeState = "normal";
  private line = "";
  private pendingCarriageReturn = false;
  private ended = false;

  constructor(private readonly sink: (text: string) => void) {}

  write(chunk: Buffer | string): void {
    const text = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    for (const character of text) this.consume(character);
  }

  end(): void {
    if (this.ended) return;
    this.ended = true;
    for (const character of this.decoder.end()) this.consume(character);
    // A trailing CR means the last progress line was overwritten.
    if (this.pendingCarriageReturn) {
      this.pendingCarriageReturn = false;
      this.line = "";
    }
    this.flushLine();
    this.state = "normal";
  }

  preview(): string {
    return this.line;
  }

  private consume(character: string): void {
    if (this.pendingCarriageReturn) {
      this.pendingCarriageReturn = false;
      if (character === "\n") {
        // CRLF is a normal newline, not a progress overwrite.
        this.line += "\n";
        this.flushLine();
        return;
      }
      this.line = "";
    }

    switch (this.state) {
      case "normal":
        this.consumeNormal(character);
        return;
      case "escape":
        this.consumeEscape(character);
        return;
      case "csi":
        // CSI ends at a final byte in the range 0x40-0x7E.
        if (character >= "\u0040" && character <= "\u007e") {
          this.state = "normal";
        }
        return;
      case "osc":
        if (character === "\u0007") {
          this.state = "normal";
        } else if (character === "\u001b") {
          this.state = "osc-escape";
        }
        return;
      case "osc-escape":
        if (character === "\\") {
          this.state = "normal";
        } else if (character !== "\u001b") {
          this.state = "osc";
        }
        return;
      case "string":
        if (character === "\u001b") this.state = "string-escape";
        return;
      case "string-escape":
        if (character === "\\") {
          this.state = "normal";
        } else if (character !== "\u001b") {
          this.state = "string";
        }
        return;
      case "charset":
        this.state = "normal";
        return;
    }
  }

  private consumeNormal(character: string): void {
    if (character === "\u001b") {
      this.state = "escape";
      return;
    }
    if (character === "\n") {
      this.line += "\n";
      this.flushLine();
      return;
    }
    if (character === "\r") {
      this.pendingCarriageReturn = true;
      return;
    }
    if (character === "\b") {
      this.line = this.line.slice(0, -1);
      return;
    }
    if (character === "\t") {
      this.push(character);
      return;
    }
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return;
    this.push(character);
  }

  private consumeEscape(character: string): void {
    if (character === "[") {
      this.state = "csi";
      return;
    }
    if (character === "]") {
      this.state = "osc";
      return;
    }
    if (character === "P" || character === "^" || character === "_") {
      this.state = "string";
      return;
    }
    if ("()*+".includes(character)) {
      this.state = "charset";
      return;
    }
    // Any other ESC sequence is a two-character sequence; drop both.
    this.state = "normal";
  }

  private push(character: string): void {
    this.line += character;
    if (this.line.length > MAX_LINE_CHARS) this.flushLine();
  }

  private flushLine(): void {
    if (this.line.length === 0) return;
    const text = this.line;
    this.line = "";
    this.sink(text);
  }
}

/**
 * Collects a bounded amount of process output. It strips terminal control
 * sequences, collapses progress-bar rewrites, and keeps both the beginning and
 * the end of long output so failures at the tail are still visible.
 */
export class OutputCollector {
  private readonly headLimit: number;
  private readonly tailLimit: number;
  private readonly head: Buffer[] = [];
  private readonly tail: Buffer[] = [];
  private headBytes = 0;
  private tailBytes = 0;
  private receivedBytes = 0;
  private cleanedBytes = 0;
  private readonly sanitizer: TerminalSanitizer;

  constructor(limitBytes: number) {
    const limit = Math.max(1, Math.trunc(limitBytes));
    this.headLimit = Math.min(limit, Math.max(64, Math.floor(limit / 4)));
    this.tailLimit = limit - this.headLimit;
    this.sanitizer = new TerminalSanitizer((text) => this.add(text));
  }

  append(chunk: Buffer | string): void {
    const buffer = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    this.receivedBytes += buffer.length;
    this.sanitizer.write(buffer);
  }

  /** Flush the sanitizer's pending line. Call once when the stream closes. */
  end(): void {
    this.sanitizer.end();
  }

  text(): string {
    const head = Buffer.concat(this.head);
    const tail = Buffer.concat(this.tail);
    const dropped = this.cleanedBytes - (this.headBytes + this.tailBytes);
    if (dropped <= 0) {
      return Buffer.concat([head, tail]).toString("utf8");
    }

    const marker = `\n[... ${dropped} bytes omitted; showing beginning and end ...]\n`;
    if (tail.length === 0) {
      return `${head.toString("utf8")}${marker}`;
    }
    return `${head.toString("utf8")}${marker}${tail.toString("utf8")}`;
  }

  /** A bounded, sanitized snapshot used for progress updates. */
  tailText(maxBytes = 2_048): string {
    const limit = Math.max(0, Math.trunc(maxBytes));
    if (limit === 0) return "";
    const chunks = this.cleanedBytes > this.headBytes + this.tailBytes
      ? this.tail
      : [...this.head, ...this.tail];
    const selected: Buffer[] = [];
    let remaining = limit;
    for (let index = chunks.length - 1; index >= 0 && remaining > 0; index -= 1) {
      const chunk = chunks[index];
      if (chunk === undefined) continue;
      const take = Math.min(chunk.length, remaining);
      selected.unshift(chunk.subarray(chunk.length - take));
      remaining -= take;
    }
    const text = Buffer.concat(selected).toString("utf8");
    const pending = this.sanitizer.preview();
    if (pending.length === 0) return text;
    return `${text}${pending}`.slice(-limit);
  }

  get truncated(): boolean {
    return this.cleanedBytes > this.headBytes + this.tailBytes;
  }

  /** Bytes received from the remote process. */
  get rawBytes(): number {
    return this.receivedBytes;
  }

  /** Bytes retained after sanitization and truncation. */
  get bytes(): number {
    return this.headBytes + this.tailBytes;
  }

  get droppedBytes(): number {
    return Math.max(0, this.cleanedBytes - this.bytes);
  }

  private add(text: string): void {
    if (text.length === 0) return;
    this.cleanedBytes += Buffer.byteLength(text, "utf8");
    let buffer = Buffer.from(text, "utf8");

    if (this.headBytes < this.headLimit) {
      const room = this.headLimit - this.headBytes;
      const take = Math.min(room, buffer.length);
      this.head.push(buffer.subarray(0, take));
      this.headBytes += take;
      buffer = buffer.subarray(take);
      if (buffer.length === 0) return;
    }

    if (this.tailLimit === 0) return;
    this.tail.push(buffer);
    this.tailBytes += buffer.length;
    while (this.tailBytes > this.tailLimit && this.tail.length > 0) {
      const first = this.tail[0];
      if (first === undefined) break;
      const excess = this.tailBytes - this.tailLimit;
      if (first.length <= excess) {
        this.tail.shift();
        this.tailBytes -= first.length;
      } else {
        this.tail[0] = first.subarray(excess);
        this.tailBytes -= excess;
      }
    }
  }
}
