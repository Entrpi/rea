import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { expect, it, vi } from "vitest";

import { OwnedCommandFailure } from "../../src/process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../../src/process/ProviderProcess.js";
import type { execFileOutput } from "../../src/process/ExecFileOutput.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { providerSnapshot } from "../support/reverseEngineeringCompositionFixtures.js";
import { TestReverseEngineeringService } from "../support/reverseEngineeringService.js";
import { digestFile } from "../../src/application/reverse/ReverseEngineeringService.js";

type ExecFileOutputOptions = NonNullable<Parameters<typeof execFileOutput>[2]>;

/** A selected executable on disk; the injected runner never executes it. */
const fixture = async () => {
  const directory = await createTestTempDirectory("rea-rizin-identity-");
  const executable = join(directory, "rizin");
  const path = join(directory, "sample.bin");
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  await writeFile(path, "sample");
  const digest = async () =>
    createHash("sha256")
      .update(await readFile(executable))
      .digest("hex");
  return { executable, path, digest };
};

const runner = (banner: () => string) =>
  vi.fn(
    async (
      _command: string,
      args: readonly string[],
      _options?: ExecFileOutputOptions,
    ) => ({
      stdout: args[0] === "-v" ? banner() : "command output",
      stderr: "",
    }),
  );

const probes = (run: ReturnType<typeof runner>) =>
  run.mock.calls.filter(([, args]) => args[0] === "-v").length;

// The selected executable is a POSIX mode-0755 file; Windows resolves
// REA_RIZIN_COMMAND separately and is not covered here.
const posix = it.skipIf(process.platform === "win32");

posix(
  "records the version from the banner, runs the file it hashed, and probes once per digest",
  async () => {
    const { executable, path, digest } = await fixture();
    const run = runner(() => "rizin 0.9.1 @ linux-x86-64\ncommit: abc");
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: "rizin", PATH: dirname(executable) },
    });
    for (const command of ["iI", "iS"]) {
      const result = await service.executeRizinCommand({
        path,
        command,
        command_timeout_ms: 4_321,
      });
      if (!result.ok) throw result.error;
      expect(result.value.provider).toEqual({
        id: "rizin",
        name: "Rizin",
        version: "0.9.1",
      });
      expect(result.value.parameters).toMatchObject({
        provider_executable: "rizin",
        provider_executable_path: executable,
        provider_executable_sha256: await digest(),
        provider_version_banner: "rizin 0.9.1 @ linux-x86-64",
      });
    }
    expect(probes(run)).toBe(1);
    // The probe and both commands spawn the resolved file, within the budget.
    expect(run.mock.calls.map(([command]) => command)).toEqual([
      executable,
      executable,
      executable,
    ]);
    expect(run.mock.calls[0]?.[2]?.timeout).toBe(4_321);

    await writeFile(executable, "#!/bin/sh\nexit 1\n");
    const changed = await service.executeRizinCommand({ path, command: "iI" });
    if (!changed.ok) throw changed.error;
    expect(changed.value.parameters.provider_executable_sha256).toBe(
      await digest(),
    );
    expect(probes(run)).toBe(2);
  },
);

posix.each([
  [
    "radare2 6.1.8 +0 abi:110 @ darwin-arm_64",
    { id: "rizin", name: "radare2", version: "6.1.8" },
    "not Rizin",
  ],
  [
    "Usage: tool [options]",
    { id: "rizin", name: "Rizin", version: null },
    "banner did not identify them",
  ],
])(
  "runs the command for banner %j and records what it identified",
  async (banner, provider, limitation) => {
    const { executable, path } = await fixture();
    const run = runner(() => banner);
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    const result = await service.executeRizinCommand({ path, command: "iI" });
    if (!result.ok) throw result.error;
    expect(result.value.provider).toEqual(provider);
    expect(result.value.parameters.provider_version_banner).toBe(banner);
    expect(result.value.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining(limitation)]),
    );
    expect(result.value.raw_result).toMatchObject({
      stdout: "command output",
    });
  },
);

posix(
  "still runs the command when the version probe fails, and reuses that result",
  async () => {
    const { executable, path } = await fixture();
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        _options?: ExecFileOutputOptions,
      ) => {
        if (args[0] === "-v")
          throw Object.assign(new Error("probe exited"), { code: 2 });
        return { stdout: "command output", stderr: "" };
      },
    );
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    for (const command of ["iI", "iS"]) {
      const result = await service.executeRizinCommand({ path, command });
      if (!result.ok) throw result.error;
      expect(result.value.provider).toEqual({
        id: "rizin",
        name: "Rizin",
        version: null,
      });
      expect(result.value.parameters).not.toHaveProperty(
        "provider_version_banner",
      );
      expect(result.value.limitations).toEqual(
        expect.arrayContaining([expect.stringContaining("(-v) failed (2)")]),
      );
    }
    expect(probes(run)).toBe(1);
  },
);

posix(
  "shares one probe between concurrent calls and keeps it for the caller that still waits",
  async () => {
    const { executable, path } = await fixture();
    let started: (() => void) | undefined;
    const running = new Promise<void>((resolveRunning) => {
      started = resolveRunning;
    });
    let releaseProbe: (() => void) | undefined;
    const release = new Promise<void>((resolveRelease) => {
      releaseProbe = resolveRelease;
    });
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        options?: ExecFileOutputOptions,
      ) => {
        if (args[0] !== "-v") return { stdout: "command output", stderr: "" };
        started?.();
        await release;
        if (options?.signal?.aborted === true)
          throw Object.assign(new Error("aborted"), { code: "ABORT_ERR" });
        return { stdout: "rizin 0.9.1 @ linux-x86-64", stderr: "" };
      },
    );
    // The second caller joins the shared probe right after it hashes the
    // executable; a macrotask after that hash proves it is waiting.
    let executableDigests = 0;
    let joined: (() => void) | undefined;
    const waiting = new Promise<void>((resolveWaiting) => {
      joined = resolveWaiting;
    });
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
      digest: async (target, ...rest) => {
        const value = await digestFile(target, ...rest);
        if (target === executable && ++executableDigests === 2)
          setImmediate(() => joined?.());
        return value;
      },
    });
    const staying = service.executeRizinCommand({ path, command: "iI" });
    await running;
    const leaving = new AbortController();
    const left = service.executeRizinCommand(
      { path, command: "iS" },
      { signal: leaving.signal },
    );
    await waiting;
    leaving.abort("second caller left");
    const leftResult = await left;
    if (leftResult.ok) throw new Error("Expected the second caller to leave");
    expect(leftResult.error._tag).toBe("AnalysisCancelledError");
    expect(leftResult.error.cause).toBe("second caller left");
    releaseProbe?.();
    const kept = await staying;
    if (!kept.ok) throw kept.error;
    expect(kept.value.provider.version).toBe("0.9.1");
    expect(probes(run)).toBe(1);
    expect(run.mock.calls.filter(([, args]) => args[0] !== "-v")).toHaveLength(
      1,
    );
  },
);

posix(
  "returns the caller's cancellation from the probe without starting the command",
  async () => {
    const { executable, path } = await fixture();
    const caller = new AbortController();
    const reason = { caller: "stop during version probe" };
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        _options?: ExecFileOutputOptions,
      ) => {
        expect(args).toEqual(["-v"]);
        caller.abort(reason);
        throw Object.assign(new Error("aborted"), { code: "ABORT_ERR" });
      },
    );
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    const result = await service.executeRizinCommand(
      { path, command: "iI" },
      { signal: caller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(result.error.cause).toBe(reason);
    expect(run).toHaveBeenCalledOnce();
  },
);

posix(
  "retains a probe whose cleanup is incomplete until its owner stops",
  async () => {
    const { executable, path } = await fixture();
    let stopped = false;
    const owner = {
      stop: async () =>
        stopped
          ? { status: "stopped" as const }
          : { status: "incomplete" as const, reason: "probe still running" },
    } as unknown as ProviderProcessSupervisor;
    const runOwned = vi.fn(
      async (request: { readonly arguments: readonly string[] }) => {
        if (request.arguments[0] === "-v")
          throw new OwnedCommandFailure(
            "process",
            "probe cleanup failed",
            providerSnapshot({
              stdout: { text: "", bytes: 0, observedBytes: 0 },
            }),
            "probe still running",
            undefined,
            ["pid:9"],
            owner,
          );
        return providerSnapshot();
      },
    );
    const service = new TestReverseEngineeringService({
      runOwned,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    const failed = await service.executeRizinCommand({ path, command: "iI" });
    expect(failed).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisOutputError",
        cleanup: { reason: "probe still running", resources: ["pid:9"] },
      },
    });
    expect(runOwned).toHaveBeenCalledOnce();

    const blocked = await service.executeRizinCommand({ path, command: "iI" });
    expect(blocked.ok).toBe(false);
    expect(runOwned).toHaveBeenCalledOnce();

    stopped = true;
    expect(await service.retryCleanup()).toEqual({ ok: true, value: null });
    expect(failed.ok ? undefined : failed.error.cleanupIncomplete).toBe(false);
  },
);
