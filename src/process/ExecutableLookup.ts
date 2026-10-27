import { constants as fsConstants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { delimiter, isAbsolute, sep } from "node:path";

import {
  absoluteCallerPath,
  appendCallerPath,
} from "../filesystem/callerPath.js";

/** Where a command resolves through an effective PATH, or why it does not. */
export type ExecutableLookup =
  | { readonly status: "found"; readonly path: string }
  /** The host refused to inspect an explicitly selected path. */
  | {
      readonly status: "denied";
      readonly path: string;
      readonly code: "EACCES" | "EPERM";
      readonly cause: unknown;
    }
  | { readonly status: "missing"; readonly checked: readonly string[] };

/**
 * Resolve a command the way process spawning searches for it. A command that
 * contains a path separator is the selected path; PATH search continues past
 * denied directories, and an existing file without execute permission is not
 * a match.
 */
export const lookupExecutable = async (
  command: string,
  workingDirectory: string,
  searchPath: string | undefined,
): Promise<ExecutableLookup> => {
  // Match Node's Unix default search path when PATH is absent. An empty
  // PATH is different: its empty component selects the working directory.
  const directories = (searchPath ?? "/usr/bin:/bin")
    .split(delimiter)
    .map((directory) =>
      directory === ""
        ? workingDirectory
        : absoluteCallerPath(directory, { cwd: workingDirectory }),
    );
  const explicit =
    isAbsolute(command) ||
    command.includes("/") ||
    (sep === "\\" && command.includes("\\"));
  const candidates = explicit
    ? [absoluteCallerPath(command, { cwd: workingDirectory })]
    : directories.map((directory) => appendCallerPath(directory, command));
  const checked: string[] = [];
  for (const candidate of candidates) {
    let metadata;
    try {
      metadata = await stat(candidate);
    } catch (cause: unknown) {
      const code = systemErrorCode(cause);
      if (explicit && (code === "EACCES" || code === "EPERM"))
        return { status: "denied", path: candidate, code, cause };
      checked.push(`${candidate}${systemErrorSuffix(code)}`);
      continue;
    }
    if (!metadata.isFile()) {
      checked.push(`${candidate} (not a regular file)`);
      continue;
    }
    try {
      await access(candidate, fsConstants.X_OK);
      return { status: "found", path: candidate };
    } catch (cause: unknown) {
      checked.push(`${candidate}${systemErrorSuffix(systemErrorCode(cause))}`);
    }
  }
  return { status: "missing", checked };
};

const systemErrorCode = (cause: unknown): string | undefined =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  typeof cause.code === "string"
    ? cause.code
    : undefined;

const systemErrorSuffix = (code: string | undefined): string =>
  code === undefined ? "" : ` (${code})`;
