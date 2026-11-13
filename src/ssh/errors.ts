export type SshErrorCode =
  | "SSH_NOT_CONNECTED"
  | "SSH_COMMAND_TIMEOUT"
  | "SSH_CONNECTION_LOST"
  | "SSH_CHANNEL_NO_EXIT"
  | "SSH_COMMAND_ABORTED"
  | "SSH_CHANNEL_ERROR"
  | "SSH_INVALID_INPUT"
  | "SSH_INTERNAL_ERROR";

export interface SshErrorDetails {
  readonly code: SshErrorCode;
  readonly retryable: boolean;
  readonly hint: string;
  readonly recommendedNextTool?: string;
  /**
   * True when the remote command may already have run and produced side
   * effects, even though this call failed. Never retry blindly in that case.
   */
  readonly executionMayHaveStarted: boolean;
}

export class SshOperationError extends Error {
  readonly code: SshErrorCode;
  readonly retryable: boolean;
  readonly hint: string;
  readonly recommendedNextTool?: string;
  readonly executionMayHaveStarted: boolean;

  constructor(message: string, details: SshErrorDetails) {
    super(message);
    this.name = "SshOperationError";
    this.code = details.code;
    this.retryable = details.retryable;
    this.hint = details.hint;
    this.executionMayHaveStarted = details.executionMayHaveStarted;
    if (details.recommendedNextTool !== undefined) {
      this.recommendedNextTool = details.recommendedNextTool;
    }
  }
}
