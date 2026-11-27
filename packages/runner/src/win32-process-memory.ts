/**
 * bcmt Windows lanes: a process's working set on Windows, read through kernel32 `K32GetProcessMemoryInfo`
 * (the same figure as `Get-Process`'s `WorkingSet64`). The lane gate and the memory guard read a daemon's
 * resident memory through `readProcessRssBytes`; `/proc` does not exist on Windows, so without this the
 * reader had no figure and lanes could not start there.
 *
 * The `bun:ffi` binding loads lazily, on the first Windows read: Linux and macOS never evaluate it.
 * `Win32MemoryApi` is the seam; tests inject a fake and never call kernel32.
 */

/** The three kernel32 calls the reader makes. `open` returns null when the process cannot be opened (e.g. it exited). */
export interface Win32MemoryApi {
  open(pid: number): unknown | null;
  read(handle: unknown): { workingSet: number } | null;
  close(handle: unknown): void;
}

/** `PROCESS_QUERY_LIMITED_INFORMATION`: enough for `K32GetProcessMemoryInfo`, and granted for most processes. */
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
/** `sizeof(PROCESS_MEMORY_COUNTERS)` on 64-bit Windows: cb + PageFaultCount (2 x u32), then 8 `size_t`. */
const PROCESS_MEMORY_COUNTERS_BYTES = 72;
/** Index of `WorkingSetSize` (byte offset 16) in the counters read as `BigUint64Array`. */
const WORKING_SET_INDEX = 2;

/** `GetExitCodeProcess`'s code for a process that is still running. */
const STILL_ACTIVE = 259;

/** The loaded api; `null` once a load has failed (every read is then undefined), undefined before the first use. */
let loadedApi: Win32MemoryApi | null | undefined;

/**
 * Binds kernel32 through `bun:ffi`. `require` (not a static import) keeps the module out of non-Windows loads.
 * Win32 `BOOL` is a 32-bit int, so it is bound as `i32` and tested with `!== 0`.
 */
function bindKernel32(): Win32MemoryApi {
  const { dlopen, FFIType, ptr } = require("bun:ffi") as typeof import("bun:ffi");
  const k = dlopen("kernel32.dll", {
    OpenProcess: { args: [FFIType.u32, FFIType.i32, FFIType.u32], returns: FFIType.ptr },
    GetExitCodeProcess: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.i32 },
    K32GetProcessMemoryInfo: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.u32],
      returns: FFIType.i32,
    },
    CloseHandle: { args: [FFIType.ptr], returns: FFIType.i32 },
  });
  type Handle = Parameters<typeof k.symbols.CloseHandle>[0];
  return {
    open(pid) {
      const handle = k.symbols.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
      return handle ? handle : null;
    },
    read(handle) {
      // A process that has just exited can still be opened while another handle holds it; it has no working set.
      const exitCode = new Uint32Array(1);
      if (k.symbols.GetExitCodeProcess(handle as Handle, ptr(exitCode)) === 0) return null;
      if (exitCode[0] !== STILL_ACTIVE) return null;
      const counters = new BigUint64Array(PROCESS_MEMORY_COUNTERS_BYTES / 8);
      new Uint32Array(counters.buffer)[0] = PROCESS_MEMORY_COUNTERS_BYTES;
      const ok = k.symbols.K32GetProcessMemoryInfo(
        handle as Handle,
        ptr(counters),
        PROCESS_MEMORY_COUNTERS_BYTES,
      );
      return ok !== 0 ? { workingSet: Number(counters[WORKING_SET_INDEX]) } : null;
    },
    close(handle) {
      k.symbols.CloseHandle(handle as Handle);
    },
  };
}

/** The lazily loaded kernel32 binding, or undefined when it cannot be loaded (cached either way). */
function kernel32Api(): Win32MemoryApi | undefined {
  if (loadedApi === undefined) {
    try {
      loadedApi = bindKernel32();
    } catch {
      loadedApi = null;
    }
  }
  return loadedApi ?? undefined;
}

/**
 * bcmt Windows lanes: a process's working set in bytes, or undefined when it cannot be read (a pid that
 * has exited, no access, kernel32 not loadable). Never throws. The handle is closed on every path that
 * opened one. `api` is injectable: tests never call kernel32.
 */
export function readWin32WorkingSetBytes(
  pid: number,
  api: Win32MemoryApi | undefined = kernel32Api(),
): number | undefined {
  if (api === undefined) return undefined;
  try {
    const handle = api.open(pid);
    if (handle === null) return undefined;
    try {
      return api.read(handle)?.workingSet;
    } finally {
      api.close(handle);
    }
  } catch {
    return undefined;
  }
}
