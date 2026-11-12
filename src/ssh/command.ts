export interface BuildCommandInput {
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  sudo?: boolean;
  asUser?: string;
  /** The SSH login user; when root, sudo is unnecessary unless switching users. */
  loginUser: string;
}

export interface BuiltCommand {
  command: string;
  usesSudo: boolean;
}

/**
 * Build the command string that is passed to the SSH server. The SSH server
 * runs it through the login user's shell, so `cd` and `export` are available.
 */
export function buildRemoteCommand(input: BuildCommandInput): BuiltCommand {
  if (input.command.trim().length === 0) {
    throw new Error("command must not be empty.");
  }

  const environment = Object.entries(input.env ?? {});
  const exports = environment
    .map(([name, value]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`Invalid environment variable name: ${name}`);
      }
      return `export ${name}=${shellQuote(value)}`;
    })
    .join("; ");

  let script = input.command;
  if (environment.length > 0 || input.cwd !== undefined) {
    // Group the command so a failed `cd` stops the entire script and exported
    // variables stay scoped to this invocation.
    script = `(${environment.length > 0 ? `${exports}; ` : ""}${input.command})`;
  }

  if (input.cwd !== undefined) {
    script = `${cwdCommand(input.cwd)} && ${script}`;
  }

  const wantsSudo = input.sudo === true || input.asUser !== undefined;
  if (!wantsSudo || (input.loginUser === "root" && input.asUser === undefined)) {
    return { command: script, usesSudo: false };
  }

  const userArgument =
    input.asUser !== undefined ? ` -u ${shellQuote(input.asUser)} -H` : "";
  return {
    // -S reads the password from stdin, so it never appears in the remote
    // process list. -p '' suppresses the prompt in captured stderr.
    command: `sudo -S -p ''${userArgument} -- sh -c ${shellQuote(script)}`,
    usesSudo: true,
  };
}

/** POSIX single-quote escaping that is safe for arbitrary command text. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function cwdCommand(value: string): string {
  const cwd = value.trim();
  if (cwd.length === 0) throw new Error("cwd must not be empty.");
  if (cwd === "~") return 'cd -- "$HOME"';
  if (cwd.startsWith("~/")) {
    const rest = cwd.slice(2);
    return rest.length === 0
      ? 'cd -- "$HOME"'
      : `cd -- "$HOME"/${shellQuote(rest)}`;
  }
  return `cd -- ${shellQuote(cwd)}`;
}

export function looksLikeMissingTty(stderr: string): boolean {
  return /no tty present|a terminal is required|must have a tty|is not a terminal|sudo: sorry, you must have a tty/i.test(
    stderr,
  );
}

export function looksLikeSudoPasswordFailure(stderr: string): boolean {
  return /no password was provided|a password is required|incorrect password|sorry, try again|sudo: \d+ incorrect password/i.test(
    stderr,
  );
}
