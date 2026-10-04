"""Signature definitions for every AAC patch site.

Each signature keys on version-invariant bytes only: opcodes, fourcc constants
('NONE','alac','flac','.mp3','ac-3'), AVCodecID values (0x1500x), and the table
entry count.  Volatile bytes -- RIP-relative disp32, branch rel32, absolute
imm32 pointers -- are wildcarded '??' so the same signature survives across
builds where those shift.

`orig`/`new` are given ONLY for edits that are a static equal-length swap.
Sites whose replacement depends on a located address (gate1's je rel32, gate3C's
recomputed jmp rel32) carry no static `new`; the caller derives what it needs
from the decoded instruction.  Those carry kind="computed".

Two lists are exported:
  SIGNATURES      the QuickTime (MP4/MOV/M4A) sites, always required
  MKV_SIGNATURES  the Matroska sites, used only with --mkv
Both are reported by `python -m aacpatch.locate`, which is the first thing to
run against an unfamiliar build.
"""
import re

from .signature import Signature


def _fourcc_le(s):
    return bytes(reversed(s.encode()))


# --- verifiers (capstone) ------------------------------------------------

def _v_cmp_imm(reg, imm):
    """Return a verifier asserting the instruction at match start is
    `cmp <reg>, <imm>`."""
    def check(cs, off, elfmap, buf):
        va = elfmap.off_to_va(off)
        insn = next(cs.disasm(buf[off:off + 15], va, count=1), None)
        if not insn or insn.mnemonic != "cmp":
            return False
        ops = insn.op_str.replace(",", "").split()
        return len(ops) == 2 and ops[0] == reg and int(ops[1], 0) == imm
    return check


def cmp_imm_reg(cs, off, elfmap, buf, imm):
    """If the instruction at `off` is `cmp r8d..r15d, <imm>`, return the 64-bit
    name of that register (what e9tool takes as a trampoline argument), else
    None.  For sites where the compiler's register choice is not stable across
    point releases, so the register is read off the binary, not assumed."""
    va = elfmap.off_to_va(off)
    insn = next(cs.disasm(buf[off:off + 15], va, count=1), None)
    if not insn or insn.mnemonic != "cmp":
        return None
    ops = insn.op_str.replace(",", "").split()
    if len(ops) != 2 or not re.fullmatch(r"r(?:[89]|1[0-5])d", ops[0]):
        return None
    try:
        if int(ops[1], 0) != imm:
            return None
    except ValueError:
        return None
    return ops[0][:-1]


def _v_cmp_reg_imm(imm):
    """Return a verifier asserting the instruction at match start is
    `cmp <r8d..r15d>, <imm>`, whichever register it is."""
    def check(cs, off, elfmap, buf):
        return cmp_imm_reg(cs, off, elfmap, buf, imm) is not None
    return check


# Every signature anchors ONLY on bytes the patch never touches (opcodes, fourcc
# constants, codec IDs, stable neighbouring instructions) and wildcards exactly
# the bytes an edit mutates.  So a signature locates its site whether the binary
# is pristine or already patched -- the applier stays idempotent.

SIGNATURES = [

    # GATE 1 -- dispatch.  Anchor on the stable '.mp3' branch: both '.mp3' and
    # 'flac' jump to the same IOAudioFFMPEGCodec handler that AAC must reach.
    #   cmp r15d,'.mp3' ; je <FFmpeg-handler>      (21.0.x - 21.1)
    #   cmp r12d,'.mp3' ; je <FFmpeg-handler>      (21.1.1)
    # The additive patcher trampolines this site ("if reg=='aac ' goto handler")
    # and reads the handler address from the je at +7.  (Anchoring only on the
    # '.mp3' branch keeps this robust to point releases that reorder the nearby
    # spare/NONE branch, which the additive path never touches.)  The ModRM
    # byte -- i.e. which register holds the fourcc -- is wildcarded because it
    # moves between point releases; the verifier pins it to `cmp r8d..r15d,
    # '.mp3'` and additive.py reads the register back via cmp_imm_reg().
    Signature(
        name="gate1_dispatch",
        pattern="41 81 ?? 33 70 6d 2e 0f 84 ?? ?? ?? ??",     # cmp '.mp3'; je
        where="exec",
        kind="computed",
        verify=_v_cmp_reg_imm(0x2e6d7033),
        desc="route 'aac ' fourcc to IOAudioFFMPEGCodec (via the '.mp3' branch)",
    ),

    # GATE 2 -- the fourcc->AVCodecID map, 4 rows x 8 bytes, in rodata.
    #   alac/0x15010  flac/0x1500c  .mp3/0x15001  ac-3/0x15003
    # Anchor on the first three (stable) rows; edit row 3 (ac-3 -> aac ).
    Signature(
        name="gate2_table",
        pattern=(_fourcc_le("alac").hex(" ") + " 10 50 01 00 " +
                 _fourcc_le("flac").hex(" ") + " 0c 50 01 00 " +
                 _fourcc_le(".mp3").hex(" ") + " 01 50 01 00"),
        where="ro",
        edit_off=24,                                   # row 3
        orig=_fourcc_le("ac-3") + bytes.fromhex("03500100"),
        new=_fourcc_le("aac ") + bytes.fromhex("02500100"),
        kind="static",
        desc="fourcc->AVCodecID table (destructive: ac-3 row -> aac )",
    ),

    # GATE 2 (additive) -- the range-insert count `mov edx, 0x4`.
    #   lea rcx,[rsp+0xf] ; mov edx,4 ; mov rdi,rbx ; call insert_range
    # Phase 3 bumps 4->5 and repoints rsi at a 5-row cave table.
    Signature(
        name="gate2_count",
        pattern="48 8d 4c 24 0f ba 04 00 00 00 48 89 df e8 ?? ?? ?? ??",
        where="exec",
        edit_off=6,
        orig=bytes.fromhex("04000000"),
        new=bytes.fromhex("05000000"),
        kind="additive",
        desc="codec-table entry count (Phase 3 additive: 4 -> 5)",
    ),

    # GATE 3A -- fetch config blob: cmp ecx, 0x1500c (FLAC) -> 0x15002 (AAC).
    # Anchor on the stable ALAC compare just above; wildcard only the FLAC imm's
    # low byte (0c/02) so it matches pristine or patched.
    #   cmp ecx,0x15010(ALAC) ; je .. ; cmp ecx,0x1500c(FLAC) ; jne ..
    Signature(
        name="gate3a_fetch",
        pattern="81 f9 10 50 01 00 74 ?? 81 f9 ?? 50 01 00 0f 85 ?? ??",
        where="exec",
        edit_off=10,                                   # imm of the FLAC cmp
        orig=bytes.fromhex("0c500100"),
        new=bytes.fromhex("02500100"),
        verify=_v_cmp_imm("ecx", 0x15010),
        desc="fetch extradata blob for AAC (was FLAC)",
    ),

    # GATE 3B -- attach it: cmp edi, 0x1500c (FLAC) -> 0x15002 (AAC).
    # Anchor on the stable ALAC compare (cmp edi,0x15010) just above.
    #   cmp edi,0x15010(ALAC) ; je .. ; cmp edi,0x1500c(FLAC) ; jne ..
    Signature(
        name="gate3b_attach",
        pattern="81 ff 10 50 01 00 0f 84 ?? ?? ?? ?? 81 ff ?? 50 01 00 0f 85 ?? ??",
        where="exec",
        edit_off=14,                                   # imm of the FLAC cmp
        orig=bytes.fromhex("0c500100"),
        new=bytes.fromhex("02500100"),
        verify=_v_cmp_imm("edi", 0x15010),
        desc="attach extradata for AAC (was FLAC)",
    ),

    # GATE 3C -- drop the 34-byte size gate.  Anchor on `sub rdx,rsi; cmp rdx,0x22`
    # (`cmp rdx,0x22` alone recurs); wildcard the branch so it matches je or the
    # patched jmp;nop.
    #   sub rdx,rsi ; cmp rdx,0x22 ; je <copy>  ->  ... ; jmp <copy> ; nop
    Signature(
        name="gate3c_sizegate",
        # The branch OPCODE is pinned (0f 84 = je) and only its rel32 is
        # wildcarded.  Leaving the opcode wildcarded meant additive.py decoded
        # whatever happened to sit there and used the result as a jump target
        # for two patches -- on a build where that decoded to a different but
        # still-parseable branch, the patcher would happily emit a binary that
        # jumps into the wrong basic block instead of refusing.
        pattern="48 29 f2 48 83 fa 22 0f 84 ?? ?? ?? ??",
        where="exec",
        edit_off=7,                                    # the je/jmp
        kind="computed",
        # patched when the branch opcode at +7 is jmp (0xE9) instead of je (0x0F)
        patched_test=lambda buf, off: buf[off + 7] == 0xE9,
        desc="drop 34-byte ALAC-cookie size constraint (je -> jmp;nop)",
    ),
]



# --- Matroska (--mkv) ----------------------------------------------------
#
# AAC was excised from the MKV path in several places at once, so these sites
# are located as a set and only used together.  They live here rather than in
# the patch driver so `aacpatch.locate` can report their health on a new build:
# "do the MKV signatures still resolve?" is the first question when a Resolve
# release breaks --mkv.
#
# All are located-only (kind="ref"): nothing is written at these offsets, they
# feed addresses to e9patch trampolines.

MKV_SIGNATURES = [
    # A_AAC parser branch: mov edi,'A_AA'; ...; xor edx,'C'; or; je <skip>.
    # Blackmagic INVERTED this branch -- on a match it jumps to the skip-track
    # loop, where AC-3/FLAC jump away on a mismatch.  That is the smoking gun.
    Signature(
        name="mkv_parser",
        pattern="bf 41 5f 41 41 31 fe 0f b6 52 04 83 f2 43 09 f2 0f 84 ?? ?? ?? ??",
        kind="ref",
        desc="A_AAC CodecID branch (the inverted `je skip`)",
    ),
    # A_AC3 parser branch, ending in `mov eax,3` -- the shared setup proceed
    # target AAC is redirected to (with codec_type forced to 1 instead of 3).
    Signature(
        name="mkv_ac3",
        pattern=("be 41 5f 41 43 31 f2 0f b6 49 04 83 f1 33 09 d1 0f 85 ?? ?? ?? ?? "
                 "b8 03 00 00 00"),
        kind="ref",
        desc="A_AC3 CodecID branch; +27 is the shared proceed path",
    ),
    # end of descriptor setup: mov [rsp+0x30],r12 ; mov [rsp+0x38],eax ; xor ebp,ebp
    Signature(
        name="mkv_setup",
        pattern="4c 89 64 24 30 89 44 24 38 31 ed",
        kind="ref",
        desc="descriptor setup end; +9 is the `xor ebp,ebp` before frame-probe",
    ),
    # AudioSpecificConfig parser prologue (reads CodecPrivate [rsi]/[rsi+8]).
    # Still present in the Linux binary -- only its caller (the AAC handler)
    # was removed, which is exactly what the Mac binary revealed.
    Signature(
        name="mkv_asc",
        pattern="55 41 56 53 48 83 ec 20 4c 89 c3 48 8b 06 8b 56 08 29 c2",
        kind="ref",
        desc="AudioSpecificConfig parser (orphaned; we restore its caller)",
    ),
    # common finalize: mov rax,[rsp+0x30]; test; je; cmp qword[rax],0; je;
    # cmp [rsp+0x3c],0
    Signature(
        name="mkv_finalize",
        pattern=("48 8b 44 24 30 48 85 c0 0f 84 ?? ?? ?? ?? 48 83 38 00 0f 84 ?? ?? ?? ?? "
                 "83 7c 24 3c 00"),
        kind="ref",
        desc="shared 'add stream' finalize the AAC handler joins",
    ),
    # F's codec dispatch: mov eax,[r15+8]; cmp eax,2; je <ctor arm>; cmp eax,3;
    # je; cmp eax,7.  The 2/3/7 codec-type sequence is unique to F.
    Signature(
        name="mkv_dispatch",
        pattern=("41 8b 47 08 83 f8 02 0f 84 ?? ?? ?? ?? 83 f8 03 0f 84 ?? ?? ?? ?? "
                 "83 f8 07"),
        kind="ref",
        desc="MKV codec-type dispatch (2/3/7 -> FFmpeg ctor; 1 = AAC is missing)",
    ),
]
