// bcmt Windows lanes: the Windows working-set reader behind `readProcessRssBytes`. A fake kernel32
// api for the logic (open / read / close), one real read of this process on Windows, and a check that
// a non-Windows platform never touches the api.
import { describe, expect, test } from "bun:test";
import { readProcessRssBytes } from "../src/al-runner-v3-baseline-check";
import { type Win32MemoryApi, readWin32WorkingSetBytes } from "../src/win32-process-memory";

/** A fake api that records what was called; `handle` null means OpenProcess failed. */
function fakeApi(opts: {
  handle: unknown | null;
  reading: { workingSet: number } | null;
  readThrows?: boolean;
}) {
  const calls: string[] = [];
  const api: Win32MemoryApi = {
    open(pid) {
      calls.push(`open:${pid}`);
      return opts.handle;
    },
    read(handle) {
      calls.push(`read:${String(handle)}`);
      if (opts.readThrows) throw new Error("boom");
      return opts.reading;
    },
    close(handle) {
      calls.push(`close:${String(handle)}`);
    },
  };
  return { api, calls };
}

describe("bcmt Windows lanes: readWin32WorkingSetBytes", () => {
  test("open fails: undefined, nothing read or closed", () => {
    const { api, calls } = fakeApi({ handle: null, reading: { workingSet: 1 } });
    expect(readWin32WorkingSetBytes(4242, api)).toBeUndefined();
    expect(calls).toEqual(["open:4242"]);
  });

  test("read fails: undefined, and the handle is closed", () => {
    const { api, calls } = fakeApi({ handle: "h1", reading: null });
    expect(readWin32WorkingSetBytes(4242, api)).toBeUndefined();
    expect(calls).toEqual(["open:4242", "read:h1", "close:h1"]);
  });

  test("reads the working set and closes the handle", () => {
    const { api, calls } = fakeApi({ handle: "h1", reading: { workingSet: 123_456_789 } });
    expect(readWin32WorkingSetBytes(4242, api)).toBe(123_456_789);
    expect(calls).toEqual(["open:4242", "read:h1", "close:h1"]);
  });

  test("a throwing read: undefined, and the handle is still closed", () => {
    const { api, calls } = fakeApi({ handle: "h1", reading: null, readThrows: true });
    expect(readWin32WorkingSetBytes(4242, api)).toBeUndefined();
    expect(calls).toEqual(["open:4242", "read:h1", "close:h1"]);
  });

  test("a throwing open: undefined, no throw", () => {
    const api: Win32MemoryApi = {
      open() {
        throw new Error("no kernel32");
      },
      read: () => null,
      close() {},
    };
    expect(readWin32WorkingSetBytes(4242, api)).toBeUndefined();
  });

  test.skipIf(process.platform !== "win32")(
    "reads this process's own working set on Windows",
    () => {
      const ws = readWin32WorkingSetBytes(process.pid);
      expect(ws).toBeGreaterThan(10 * 1024 * 1024);
    },
  );

  test.skipIf(process.platform !== "win32")("a pid that does not exist: undefined", () => {
    expect(readWin32WorkingSetBytes(0x7ffffff0)).toBeUndefined();
  });
});

describe("bcmt Windows lanes: readProcessRssBytes by platform", () => {
  test("on linux the win32 reader is never used; /proc is read", () => {
    const status = "Name:\tal-runner\nVmRSS:\t 2048 kB\n";
    const win32 = () => {
      throw new Error("the win32 reader must not be touched on linux");
    };
    expect(readProcessRssBytes(42, () => status, "linux", win32)).toBe(2048 * 1024);
  });

  test("on win32 the win32 reader answers and /proc is never read", () => {
    const read = () => {
      throw new Error("/proc must not be read on win32");
    };
    expect(readProcessRssBytes(42, read, "win32", (pid) => pid * 1000)).toBe(42_000);
    expect(readProcessRssBytes(42, read, "win32", () => undefined)).toBeUndefined();
  });
});
