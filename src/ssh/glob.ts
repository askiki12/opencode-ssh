import picomatch from "picomatch";

/**
 * Raised when a user-supplied glob cannot be compiled. Callers should surface
 * this as an input error instead of an empty search result.
 */
export class InvalidGlobPatternError extends Error {
  constructor(
    readonly pattern: string,
    message: string,
  ) {
    super(message);
    this.name = "InvalidGlobPatternError";
  }
}

export type GlobMatcher = (relativePath: string) => boolean;

const OPTIONS = {
  dot: true,
  nonegate: true,
  nocomment: true,
} as picomatch.PicomatchOptions;

/**
 * Compile a POSIX-path glob using picomatch. Matching is always done against a
 * path relative to the search root, so `*.ts` stays at the root level and
 * `**\/*.ts` is used for recursion. Hidden entries are filtered separately so
 * that `include_hidden` controls traversal rather than glob syntax.
 */
export function compileGlob(pattern: string): GlobMatcher {
  if (pattern.length === 0) {
    throw new InvalidGlobPatternError(
      pattern,
      "Invalid glob pattern: the pattern must not be empty.",
    );
  }

  let matcher: picomatch.Matcher;
  try {
    // picomatch treats some malformed patterns as a matcher that never
    // matches; makeRe exposes that as the "$^" expression.
    const expression = picomatch.makeRe(pattern, OPTIONS);
    if (expression === undefined || expression.source === "$^") {
      throw new Error("the pattern has invalid syntax or cannot match any path");
    }
    matcher = picomatch(pattern, OPTIONS);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new InvalidGlobPatternError(
      pattern,
      `Invalid glob pattern ${JSON.stringify(pattern)}: ${detail}`,
    );
  }

  return (relativePath: string): boolean => matcher(relativePath);
}
