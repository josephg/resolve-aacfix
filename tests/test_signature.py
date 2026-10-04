"""Unit tests for the signature engine.

These cover the safety contract rather than the patch logic: the patcher writes
to a 653 MB binary inside a working Resolve install, so "found exactly one site,
and it disassembles to what we expect" is the only thing standing between a
correct patch and a corrupted install.  A signature that silently matched twice,
or matched the wrong thing, would be the worst possible failure -- hence the
0-hit and >1-hit cases are tested explicitly.

Run: python -m pytest tests/   (PYTHONPATH=.:vendor/pylibs)
"""
import pytest

from aacpatch.signature import Signature, parse_pattern, _find_all_masked
from aacpatch.sites import SIGNATURES, cmp_imm_reg


class FakeElfMap:
    """Minimal ElfMap stand-in: one exec range covering the whole buffer."""

    def __init__(self, size, base=0x400000, off=0):
        self._r = [(off, size, base + off)]
        self._base, self._off = base, off

    def exec_ranges(self):
        return self._r

    def ro_ranges(self):
        return []

    def off_to_va(self, o):
        return self._base + o


# --- parse_pattern -------------------------------------------------------

def test_parse_pattern_fixed_and_wildcard():
    pat, mask = parse_pattern("de ad ?? ef")
    assert pat == b"\xde\xad\x00\xef"
    assert mask == b"\xff\xff\x00\xff"


@pytest.mark.parametrize("wild", ["??", "XX", "xx"])
def test_parse_pattern_wildcard_spellings(wild):
    _, mask = parse_pattern(f"01 {wild} 02")
    assert mask == b"\xff\x00\xff"


def test_parse_pattern_rejects_garbage():
    with pytest.raises(ValueError):
        parse_pattern("de ad zz")


# --- the masked search ---------------------------------------------------

def test_find_all_masked_finds_every_hit():
    pat, mask = parse_pattern("aa ?? cc")
    buf = b"\x00\xaa\x01\xcc\x00\xaa\x99\xcc\x00"
    assert list(_find_all_masked(buf, pat, mask, 0)) == [1, 5]


def test_find_all_masked_anchors_on_the_longest_fixed_run():
    # The engine picks the longest run of fixed bytes to scan for.  If it
    # anchored on a single byte instead, a 653 MB scan would be unusably slow --
    # and, more subtly, a pattern that begins with a wildcard would be skipped
    # near the start of the buffer.
    pat, mask = parse_pattern("?? 11 22 33 44 ??")
    buf = b"\x99\x11\x22\x33\x44\x99" + b"\x00" * 16
    assert list(_find_all_masked(buf, pat, mask, 0)) == [0]


def test_find_all_masked_requires_a_fixed_anchor():
    pat, mask = parse_pattern("?? ?? ??")
    with pytest.raises(ValueError):
        list(_find_all_masked(b"\x00" * 8, pat, mask, 0))


# --- Signature.locate: the safety contract -------------------------------

def _sig(pattern, **kw):
    return Signature(name="t", pattern=pattern, **kw)


def test_locate_returns_the_single_hit():
    buf = b"\x00" * 32 + b"\xde\xad\xbe\xef" + b"\x00" * 32
    assert _sig("de ad be ef").locate(buf, FakeElfMap(len(buf))) == 32


def test_locate_refuses_when_absent():
    buf = b"\x00" * 64
    with pytest.raises(LookupError, match="not found"):
        _sig("de ad be ef").locate(buf, FakeElfMap(len(buf)))


def test_locate_refuses_when_ambiguous():
    # Two matches must be an error, never "take the first".  A build where a
    # signature became ambiguous is exactly a build we do not understand.
    buf = b"\xde\xad\xbe\xef" + b"\x00" * 16 + b"\xde\xad\xbe\xef"
    with pytest.raises(LookupError, match="ambiguous"):
        _sig("de ad be ef").locate(buf, FakeElfMap(len(buf)))


def test_locate_only_searches_the_declared_segment_class():
    # A code signature must not match identical bytes sitting in rodata.
    buf = b"\xde\xad\xbe\xef" + b"\x00" * 16
    em = FakeElfMap(len(buf))
    em._r = []                       # no executable ranges at all
    with pytest.raises(LookupError):
        _sig("de ad be ef", where="exec").locate(buf, em)


def test_equal_length_edit_is_enforced():
    # An in-place edit of a different length would shift every following byte.
    with pytest.raises(ValueError, match="length"):
        Signature(name="t", pattern="90", orig=b"\x01\x02", new=b"\x03")


# --- gate1: the fourcc register varies by build --------------------------

GATE1 = next(s for s in SIGNATURES if s.name == "gate1_dispatch")
MP3 = 0x2e6d7033


def _gate1_buf(modrm):
    # cmp <r/m32 per modrm>, '.mp3' ; je +0x10, padded with nops
    site = bytes([0x41, 0x81, modrm]) + b"3pm." + b"\x0f\x84\x10\x00\x00\x00"
    return b"\x90" * 16 + site + b"\x90" * 16


@pytest.mark.parametrize("modrm,reg", [(0xff, "r15"),     # 21.0.x - 21.1
                                       (0xfc, "r12")])    # 21.1.1
def test_gate1_locates_whichever_register_holds_the_fourcc(modrm, reg):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    buf = _gate1_buf(modrm)
    em = FakeElfMap(len(buf))
    off = GATE1.locate(buf, em)
    assert off == 16
    # ... and the register the trampoline is given is the one in the binary
    assert cmp_imm_reg(Cs(CS_ARCH_X86, CS_MODE_64), off, em, buf, MP3) == reg


@pytest.mark.parametrize("modrm", [0x3f,     # cmp dword ptr [r15], '.mp3'
                                   0xc7])    # add r15d, '.mp3'
def test_gate1_refuses_what_is_not_a_register_compare(modrm):
    # Same surrounding bytes, but no register holding the fourcc to hand the
    # trampoline: the wildcarded ModRM must not let these through.
    buf = _gate1_buf(modrm)
    with pytest.raises(LookupError, match="verification"):
        GATE1.locate(buf, FakeElfMap(len(buf)))
