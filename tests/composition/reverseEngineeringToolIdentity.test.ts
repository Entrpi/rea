import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { expect, it, vi } from "vitest";

import { OwnedCommandFailure } from "../../src/process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../../src/process/ProviderProcess.js";
import type { execFileOutput } from "../../src/process/ExecFileOutput.js";
import { awaitAcknowledgement } from "../fixtures/lifecycleAcknowledgement.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { providerSnapshot } from "../support/reverseEngineeringCompositionFixtures.js";
import { TestReverseEngineeringService } from "../support/reverseEngineeringService.js";
import { createReverseEngineeringCommandPort } from "../../src/composition/reverseEngineering.js";

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

/** Wait for launched work, failing instead of hanging past a bounded deadline. */
const within = async <Value>(
  operation: Promise<Value>,
  boundary: string,
): Promise<Value> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${boundary} did not settle in time`)),
          2_000,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

/** A gate that a test releases, registered before the work that waits on it. */
const gate = () => {
  let open: (() => void) | undefined;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open: () => open?.() };
};

// The selected executable is a POSIX mode-0755 file; Windows resolves
// REA_RIZIN_COMMAND separately and is not covered here.
const posix = it.skipIf(process.platform === "win32");

posix(
  "records the version from the banner, runs the path it hashed, and probes once per path and digest",
  async () => {
    const { executable, path, digest } = await fixture();
    // Homebrew's Rizin 0.9.1 printed this banner, package suffix included.
    const banner = "rizin 0.9.1 @ darwin-arm-64, package: 0.9.1_2 (Homebrew)";
    const run = runner(() => `${banner}\ncommit: abc`);
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
        provider_version_banner: banner,
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
  "keeps a failed probe's exit and output, runs the command, and reuses that result",
  async () => {
    const { executable, path } = await fixture();
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        _options?: ExecFileOutputOptions,
      ) => {
        if (args[0] === "-v")
          throw Object.assign(new Error("probe exited"), {
            code: 2,
            signal: null,
            stdout: "usage: tool [options]\n",
            stderr: "unknown option -v\n",
          });
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
      expect(result.value.parameters).toMatchObject({
        provider_executable_path: executable,
        provider_version_probe: {
          exit_code: 2,
          signal: null,
          stdout: "usage: tool [options]\n",
          stderr: "unknown option -v\n",
          output_truncated: false,
        },
      });
      expect(result.value.parameters).not.toHaveProperty(
        "provider_version_banner",
      );
      expect(result.value.raw_result).toMatchObject({
        stdout: "command output",
      });
    }
    expect(probes(run)).toBe(1);
  },
);

posix(
  "runs each caller's probe under its own deadline and cancellation",
  async () => {
    const { executable, path } = await fixture();
    const firstStarted = gate();
    const secondStarted = gate();
    const release = gate();
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        options?: ExecFileOutputOptions,
      ) => {
        if (args[0] !== "-v") return { stdout: "command output", stderr: "" };
        (probes(run) === 1 ? firstStarted : secondStarted).open();
        const signal = options?.signal;
        const aborted = new Promise<"aborted">((resolve) => {
          if (signal?.aborted === true) resolve("aborted");
          signal?.addEventListener("abort", () => resolve("aborted"), {
            once: true,
          });
        });
        if ((await Promise.race([release.opened, aborted])) === "aborted")
          throw Object.assign(new Error("aborted"), { code: "ABORT_ERR" });
        return { stdout: "rizin 0.9.1 @ linux-x86-64", stderr: "" };
      },
    );
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    const leaving = new AbortController();
    const pending: Promise<unknown>[] = [];
    try {
      const first = service.executeRizinCommand(
        { path, command: "iI", command_timeout_ms: 1_234 },
        { signal: leaving.signal },
      );
      pending.push(first);
      await awaitAcknowledgement(firstStarted.opened, first, "first probe");
      const second = service.executeRizinCommand({
        path,
        command: "iS",
        command_timeout_ms: 5_678,
      });
      pending.push(second);
      await awaitAcknowledgement(secondStarted.opened, second, "second probe");
      leaving.abort("first caller left");
      const left = await within(first, "cancelled first call");
      if (left.ok) throw new Error("Expected the first caller to be cancelled");
      expect(left.error._tag).toBe("AnalysisCancelledError");
      expect(left.error.cause).toBe("first caller left");
      release.open();
      const kept = await within(second, "second call");
      if (!kept.ok) throw kept.error;
      expect(kept.value.provider.version).toBe("0.9.1");
      const probeCalls = run.mock.calls.filter(([, args]) => args[0] === "-v");
      expect(probeCalls.map(([, , options]) => options?.timeout)).toEqual([
        1_234, 5_678,
      ]);
      expect(probeCalls[0]?.[2]?.signal).not.toBe(probeCalls[1]?.[2]?.signal);
      // The completed probe is reused; the cancelled one was never kept.
      const reused = await within(
        service.executeRizinCommand({ path, command: "iz" }),
        "reusing call",
      );
      if (!reused.ok) throw reused.error;
      expect(probes(run)).toBe(2);
    } finally {
      release.open();
      leaving.abort("test cleanup");
      await Promise.allSettled(pending);
      await service.close();
    }
  },
);

posix.each([
  { first: "success", second: "timeout" },
  { first: "exit", second: "success" },
] as const)(
  "keeps the successful reading when concurrent probes end in $first then $second",
  async ({ first: firstEnds, second: secondEnds }) => {
    const { executable, path } = await fixture();
    const started = [gate(), gate()] as const;
    const release = [gate(), gate()] as const;
    const ends = [firstEnds, secondEnds] as const;
    const run = vi.fn(
      async (
        _command: string,
        args: readonly string[],
        _options?: ExecFileOutputOptions,
      ) => {
        if (args[0] !== "-v") return { stdout: "command output", stderr: "" };
        const index = probes(run) === 1 ? 0 : 1;
        started[index].open();
        await release[index].opened;
        if (ends[index] === "success")
          return { stdout: "rizin 0.9.1 @ linux-x86-64", stderr: "" };
        throw Object.assign(
          new Error("probe failed"),
          ends[index] === "timeout"
            ? { code: "ETIMEDOUT", signal: "SIGTERM", stdout: "", stderr: "" }
            : { code: 2, signal: null, stdout: "", stderr: "usage\n" },
        );
      },
    );
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
    });
    const pending: Promise<unknown>[] = [];
    try {
      const first = service.executeRizinCommand({ path, command: "iI" });
      pending.push(first);
      await awaitAcknowledgement(started[0].opened, first, "first probe");
      const second = service.executeRizinCommand({ path, command: "iS" });
      pending.push(second);
      await awaitAcknowledgement(started[1].opened, second, "second probe");
      // Each call reports its own probe, in the order the probes end.
      for (const [index, call] of [first, second].entries()) {
        release[index]?.open();
        const result = await within(call, `call ${String(index + 1)}`);
        if (!result.ok) throw result.error;
        expect(result.value.provider.version).toBe(
          ends[index] === "success" ? "0.9.1" : null,
        );
      }
      const later = await within(
        service.executeRizinCommand({ path, command: "iz" }),
        "later call",
      );
      if (!later.ok) throw later.error;
      expect(later.value.provider).toEqual({
        id: "rizin",
        name: "Rizin",
        version: "0.9.1",
      });
      expect(probes(run)).toBe(2);
    } finally {
      for (const each of release) each.open();
      await Promise.allSettled(pending);
      await service.close();
    }
  },
);

posix("keys completed probes by launch path as well as digest", async () => {
  const { executable, path } = await fixture();
  const other = join(dirname(executable), "other");
  await mkdir(other);
  const twin = join(other, "rizin");
  await writeFile(twin, await readFile(executable), { mode: 0o755 });
  const run = vi.fn(
    async (
      command: string,
      args: readonly string[],
      _options?: ExecFileOutputOptions,
    ) => ({
      stdout:
        args[0] !== "-v"
          ? "command output"
          : command === twin
            ? "rizin 0.8.0 @ linux-x86-64"
            : "rizin 0.9.1 @ linux-x86-64",
      stderr: "",
    }),
  );
  // One service, so its cache spans the calls; each call selects a launcher.
  let selected = executable;
  const service = new TestReverseEngineeringService({
    run,
    commands: {
      objdump: (input) =>
        createReverseEngineeringCommandPort({}).objdump(input),
      rizin: (input) =>
        createReverseEngineeringCommandPort({
          REA_RIZIN_COMMAND: selected,
        }).rizin(input),
    },
  });
  const versions: unknown[] = [];
  try {
    for (const launcher of [executable, twin, executable]) {
      selected = launcher;
      const result = await service.executeRizinCommand({ path, command: "iI" });
      if (!result.ok) throw result.error;
      versions.push(result.value.provider.version);
    }
  } finally {
    await service.close();
  }
  expect(versions).toEqual(["0.9.1", "0.8.0", "0.9.1"]);
  // Byte-identical launchers in different directories are probed apart, and
  // each launcher's completed probe is reused.
  expect(
    run.mock.calls
      .filter(([, args]) => args[0] === "-v")
      .map(([command]) => command),
  ).toEqual([executable, twin]);
});

posix.each(["cancellation", "deadline"] as const)(
  "stops a stalled executable lookup on its %s without running anything",
  async (interruption) => {
    const { executable, path } = await fixture();
    const lookupStarted = gate();
    const release = gate();
    const run = runner(() => "rizin 0.9.1 @ linux-x86-64");
    const service = new TestReverseEngineeringService({
      run,
      environment: { REA_RIZIN_COMMAND: executable },
      // Only the executable's lookup stalls, as on an unresponsive PATH mount.
      stat: async (target) => {
        if (target === executable) {
          lookupStarted.open();
          await release.opened;
        }
        return stat(target);
      },
    });
    const caller = new AbortController();
    const pending: Promise<unknown>[] = [];
    try {
      const call = service.executeRizinCommand(
        {
          path,
          command: "iI",
          ...(interruption === "deadline" ? { command_timeout_ms: 50 } : {}),
        },
        { signal: caller.signal },
      );
      pending.push(call);
      await awaitAcknowledgement(
        lookupStarted.opened,
        call,
        "executable lookup",
      );
      if (interruption === "cancellation") caller.abort("stop the lookup");
      const result = await within(call, "interrupted call");
      if (result.ok) throw new Error("Expected the lookup to be interrupted");
      expect(result.error._tag).toBe(
        interruption === "cancellation"
          ? "AnalysisCancelledError"
          : "AnalysisTimeoutError",
      );
      if (interruption === "cancellation")
        expect(result.error.cause).toBe("stop the lookup");
      expect(run).not.toHaveBeenCalled();
      // Closing does not wait for the abandoned file-system call.
      await within(service.close(), "service close");
    } finally {
      release.open();
      caller.abort("test cleanup");
      await Promise.allSettled(pending);
      await service.close();
    }
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
    expect(result.error.diagnostics).toMatchObject({ phase: "version_probe" });
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
