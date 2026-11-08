"""Win32 process attach, module enumeration and raw memory access via ctypes."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys
from dataclasses import dataclass
from typing import Iterator

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
WRITABLE = {0x04, 0x08, 0x40, 0x80}

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

VALUE_FORMATS = {
    "u8": "<B", "i8": "<b",
    "u16": "<H", "i16": "<h",
    "u32": "<I", "i32": "<i",
    "u64": "<Q", "i64": "<q",
    "f32": "<f", "f64": "<d",
}


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


def _k32():
    if sys.platform != "win32":
        raise OSError("hfw_trainer requires Windows")
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = wt.HANDLE
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k.CloseHandle.argtypes = [wt.HANDLE]
    k.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                 ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    return k


@dataclass(frozen=True)
class Module:
    name: str
    base: int
    size: int
    path: str


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    protect: int
    type: int

    @property
    def writable(self) -> bool:
        return self.protect in WRITABLE


def find_pid(exe_name: str) -> int | None:
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == exe_name.lower():
                return entry.th32ProcessID
            ok = k.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k.CloseHandle(snap)
    return None


def is_elevated(pid: int | None = None) -> bool:
    """True if `pid` (default: this process) has an elevated (Administrator) token."""
    k = _k32()
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                        wt.DWORD, ctypes.POINTER(wt.DWORD)]
    k.GetCurrentProcess.restype = wt.HANDLE
    proc = k.GetCurrentProcess() if pid is None else k.OpenProcess(0x1000, False, pid)
    if not proc:
        return False
    tok = wt.HANDLE()
    try:
        if not adv.OpenProcessToken(proc, 0x0008, ctypes.byref(tok)):  # TOKEN_QUERY
            return False
        val, n = wt.DWORD(), wt.DWORD()
        ok = adv.GetTokenInformation(tok, 20, ctypes.byref(val), 4, ctypes.byref(n))  # TokenElevation
        k.CloseHandle(tok)
        return bool(ok and val.value)
    finally:
        if pid is not None:
            k.CloseHandle(proc)


class GameProcess:
    """An open handle to a running process with typed read/write helpers."""

    def __init__(self, pid: int, *, write: bool = True):
        self._k = _k32()
        self.pid = pid
        access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        if write:
            access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        handle = self._k.OpenProcess(access, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == 5 and is_elevated(pid) and not is_elevated():
                raise PermissionError(
                    5, f"Access denied: PID {pid} runs as Administrator, so this tool must too")
            raise ctypes.WinError(err)
        self.handle = handle

    @classmethod
    def attach(cls, exe_name: str, *, write: bool = True) -> "GameProcess":
        pid = find_pid(exe_name)
        if pid is None:
            raise ProcessLookupError(f"{exe_name} is not running")
        return cls(pid, write=write)

    def close(self) -> None:
        if self.handle:
            self._k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- modules / regions -------------------------------------------------

    def modules(self) -> list[Module]:
        snap = self._k.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        if snap == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        out = []
        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = self._k.Module32FirstW(snap, ctypes.byref(entry))
            while ok:
                out.append(Module(entry.szModule, entry.modBaseAddr or 0,
                                  entry.modBaseSize, entry.szExePath))
                ok = self._k.Module32NextW(snap, ctypes.byref(entry))
        finally:
            self._k.CloseHandle(snap)
        return out

    def module(self, name: str) -> Module:
        for m in self.modules():
            if m.name.lower() == name.lower():
                return m
        raise KeyError(f"module {name} not loaded")

    def regions(self, *, writable_only: bool = False, private_only: bool = False) -> Iterator[Region]:
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        max_addr = 0x7FFF_FFFF_FFFF
        while addr < max_addr:
            if not self._k.VirtualQueryEx(self.handle, ctypes.c_void_p(addr),
                                          ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            protect = mbi.Protect
            if (mbi.State == MEM_COMMIT and not protect & PAGE_GUARD
                    and (protect & 0xFF) in READABLE):
                region = Region(base, size, protect & 0xFF, mbi.Type)
                if (not writable_only or region.writable) and \
                        (not private_only or mbi.Type == MEM_PRIVATE):
                    yield region
            addr = base + size

    # -- raw / typed access ------------------------------------------------

    def read(self, address: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t()
        if not self._k.ReadProcessMemory(self.handle, ctypes.c_void_p(address), buf, size,
                                         ctypes.byref(got)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buf.raw[: got.value]

    def write(self, address: int, data: bytes) -> None:
        got = ctypes.c_size_t()
        if not self._k.WriteProcessMemory(self.handle, ctypes.c_void_p(address), data, len(data),
                                          ctypes.byref(got)):
            raise ctypes.WinError(ctypes.get_last_error())

    def read_value(self, address: int, vtype: str):
        fmt = VALUE_FORMATS[vtype]
        return struct.unpack(fmt, self.read(address, struct.calcsize(fmt)))[0]

    def write_value(self, address: int, vtype: str, value) -> None:
        self.write(address, struct.pack(VALUE_FORMATS[vtype], value))

    def read_ptr(self, address: int) -> int:
        return self.read_value(address, "u64")
