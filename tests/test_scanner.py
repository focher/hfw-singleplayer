import ctypes
import os
import struct
import sys

import pytest

from hfw_trainer.scanner import aob_offsets, compare, compile_aob, find_value_offsets, pack_value


def test_find_value_offsets_aligned():
    data = b"\x00" * 3 + struct.pack("<i", 1234) + b"\x00" + struct.pack("<i", 1234)
    assert find_value_offsets(data, struct.pack("<i", 1234), align=1) == [3, 8]
    assert find_value_offsets(data, struct.pack("<i", 1234), align=4) == [8]


def test_aob_wildcards():
    data = bytes.fromhex("90 48 8B 05 11 22 33 44 C3 48 8B 05 AA BB CC DD")
    assert aob_offsets(data, "48 8B 05 ?? ?? ?? ??") == [1, 9]
    assert aob_offsets(data, "48 8B 05 AA ? ?? DD") == [9]
    assert compile_aob("2E").fullmatch(b".")
    assert not compile_aob("2E").fullmatch(b"x")


def test_compare_modes():
    assert compare("increased", 5, 6)
    assert compare("eq", 0, 7, 7)
    assert not compare("unchanged", 1, 2)


def test_pack_value():
    assert pack_value("i32", "0x10") == struct.pack("<i", 16)
    assert pack_value("f32", "1.5") == struct.pack("<f", 1.5)


@pytest.mark.skipif(sys.platform != "win32", reason="needs Win32 APIs")
def test_scan_own_process():
    """End-to-end: attach to this Python process, find, narrow, write, and freeze a value."""
    from hfw_trainer.process import GameProcess
    from hfw_trainer.scanner import Scanner

    marker = 0x5EED_C0DE  # unusual value -> few false hits
    cell = ctypes.c_int32(marker)
    addr = ctypes.addressof(cell)
    with GameProcess(os.getpid()) as proc:
        scanner = Scanner(proc)
        session = scanner.first_scan("i32", marker)
        assert addr in session.addresses
        cell.value = marker + 7
        session = scanner.next_scan(session, "increased")
        session = scanner.next_scan(session, "eq", marker + 7)
        assert addr in session.addresses
        proc.write_value(addr, "i32", 999)
        assert cell.value == 999
