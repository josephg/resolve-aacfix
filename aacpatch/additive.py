"""Apply the fully-additive AAC patch set via e9patch.

Derives every version-specific address from the signature engine, then invokes
e9tool with purely-additive trampolines.  Five for the QuickTime path:

  gate1  route 'aac ' fourcc to the FFmpeg codec handler   (NONE preserved)
  gate2  rebuild the fourcc->AVCodecID map with 5 entries    (AC-3 preserved)
  gate3a let AAC through the extradata FETCH                 (FLAC preserved)
  gate3b let AAC through the extradata COPY (skips size gate)(FLAC/ALAC preserved)
  gate4  rewrite the esds config blob down to the bare ASC   (FFmpeg wants ASC)

and three more with --mkv, for Matroska:

  mkv_undrop  un-drop A_AAC at the CodecID parser, codec_type = 1
  mkv_asc     parse CodecPrivate as an AudioSpecificConfig instead of
              frame-probing, and double the rate for explicit SBR/PS
  dispatch    give codec_type 1 an arm in F's codec dispatch

Nothing upstream is overwritten; each site only acts on AAC and otherwise runs
the original instruction. gate3c (the 34-byte size gate) is left untouched.

    python -m aacpatch.additive <in-binary> -o <out-binary> [--mkv]
"""
import argparse
import os
import re
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from .elfmap import ElfMap
from .sites import SIGNATURES, MKV_SIGNATURES, cmp_imm_reg

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# e9tool location: env override (AAC_E9TOOL) wins, else the vendored copy that
# CI builds into vendor/ (and that release tarballs ship).  E9DIR is the
# directory we run e9tool/e9compile from -- e9compile.sh resolves examples/
# and stdlib.c relative to it, so building from source needs a full e9patch
# checkout there, not just the two binaries.
E9TOOL = os.environ.get("AAC_E9TOOL") or \
    os.path.join(ROOT, "vendor", "e9patch", "e9tool")
E9DIR = os.path.dirname(E9TOOL)
# Prebuilt trampoline (AAC_TRAMPOLINE): if set, skip compilation and use it.
# Release tarballs always set it, so no compiler is needed to install.
PREBUILT_TRAMPOLINE = os.environ.get("AAC_TRAMPOLINE")
TRAMPOLINE_SRC = os.path.join(ROOT, "src", "trampoline", "aacadd.c")
TRAMPOLINE_BIN = PREBUILT_TRAMPOLINE or os.path.join(ROOT, "vendor", "aacadd")
PROBE_SRC = os.path.join(ROOT, "tools", "mkvprobe.c")
PROBE_BIN = os.path.join(ROOT, "vendor", "mkvprobe")

AAC_FOURCC = 0x61616320
AAC_CODEC_ID = 0x15002


def _sig(name):
    return next(s for s in SIGNATURES if s.name == name)


def resolve_addresses(buf, em):
    """Return the dict of version-specific QuickTime addresses the trampolines
    need, located by signature (raises LookupError if any site is missing)."""
    cs = Cs(CS_ARCH_X86, CS_MODE_64)

    def va(o):
        return em.off_to_va(o)

    # Instructions we are willing to read a jump/call target out of.  Decoding
    # blind and trusting whatever comes back is how a wrong-but-parseable
    # instruction on an unknown build turns into a silently mis-patched binary.
    _BRANCHES = {"je", "jne", "jmp", "call", "jz", "jnz"}

    def target_of(o, want=None):
        """Absolute branch/call target of the instruction at file offset o.
        Raises LookupError unless it really is a branch/call to an immediate."""
        insn = next(cs.disasm(buf[o:o + 8], va(o), count=1), None)
        if insn is None:
            raise LookupError(f"cannot decode instruction at file offset {o:#x}")
        allowed = want or _BRANCHES
        if insn.mnemonic not in allowed:
            raise LookupError(
                f"expected {'/'.join(sorted(allowed))} at {va(o):#x}, "
                f"found '{insn.mnemonic} {insn.op_str}'")
        try:
            return int(insn.op_str, 0)
        except ValueError as e:
            raise LookupError(f"non-immediate branch target at {va(o):#x}: "
                              f"'{insn.mnemonic} {insn.op_str}'") from e

    g1 = _sig("gate1_dispatch").locate(buf, em)      # '.mp3' cmp (anchor)
    g2 = _sig("gate2_count").locate(buf, em)
    g3a = _sig("gate3a_fetch").locate(buf, em)
    g3b = _sig("gate3b_attach").locate(buf, em)
    g3c = _sig("gate3c_sizegate").locate(buf, em)

    # The register holding the fourcc at gate1 is the compiler's choice and
    # changes between point releases (r15d up to 21.1, r12d in 21.1.1).
    g1_reg = cmp_imm_reg(cs, g1, em, buf, 0x2e6d7033)
    if g1_reg is None:
        raise LookupError(f"gate1_dispatch: no `cmp r8d..r15d, '.mp3'` at "
                          f"{va(g1):#x}")

    return {
        # gate1: match the '.mp3' cmp; AAC -> FFmpeg handler (the '.mp3' je target)
        "g1_site":    va(g1),
        "g1_reg":     g1_reg,
        "g1_target":  target_of(g1 + 7, {"je"}),
        # gate2: after the insert_range call; rbx = map; call target = insert_range
        "after_call": va(g2 + 18),
        "insert":     target_of(g2 + 13, {"call"}),
        # gate3a: match 'cmp ecx,0x1500c'; AAC -> FETCH (the ALAC short-je target)
        "a_site":     va(g3a + 8),
        "fetch":      target_of(g3a + 6, {"je"}),
        # gate3b: match 'cmp edi,0x1500c'; AAC -> COPY (gate3c's je target)
        "b_site":     va(g3b + 12),
        "copy":       target_of(g3c + 7, {"je"}),
    }


def _e9compile(src, out_bin):
    """Compile a trampoline with e9compile.sh.  Must run with cwd=E9DIR: the
    script passes `-I examples/` relative to the working directory and drops its
    output there, so E9DIR has to be a full e9patch checkout, not just the two
    binaries.  Release tarballs ship the compiled trampoline instead and never
    reach this."""
    if not os.path.exists(os.path.join(E9DIR, "e9compile.sh")):
        raise RuntimeError(
            f"no e9compile.sh in {E9DIR}: compiling the trampoline needs a full "
            "e9patch checkout there (scripts/dev-setup.sh builds one). "
            "Set AAC_TRAMPOLINE to a prebuilt trampoline to skip compilation.")
    subprocess.run(["./e9compile.sh", src], cwd=E9DIR, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    base = os.path.splitext(os.path.basename(src))[0]
    built = os.path.join(E9DIR, base)
    if os.path.exists(built):
        os.replace(built, out_bin)
    junk = os.path.join(E9DIR, base + ".o")
    if os.path.exists(junk):
        os.remove(junk)
    if not os.path.exists(out_bin):
        raise RuntimeError(f"{base} build produced no output")


def compile_trampoline():
    """Build vendor/aacadd via e9compile.sh (idempotent).  A no-op when a
    prebuilt trampoline is supplied (AAC_TRAMPOLINE) -- packaged installs ship
    the compiled trampoline and don't carry the e9patch build tree."""
    if PREBUILT_TRAMPOLINE:
        if not os.path.exists(PREBUILT_TRAMPOLINE):
            raise RuntimeError(f"AAC_TRAMPOLINE not found: {PREBUILT_TRAMPOLINE}")
        return
    _e9compile(TRAMPOLINE_SRC, TRAMPOLINE_BIN)


# The MKV site signatures live in sites.py alongside the QuickTime ones so that
# `python -m aacpatch.locate` can report on both.  Keyed by the short name the
# address derivation below uses.
_MKV_SIGS = {s.name.removeprefix("mkv_"): s for s in MKV_SIGNATURES}


def resolve_mkv(buf, em):
    """Locate the MKV sites by signature; return the address dict."""
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    loc = {k: s.locate(buf, em) for k, s in _MKV_SIGS.items()}

    def va(o):
        return em.off_to_va(o)

    def branch_target(o):
        """Decoded target of the `je` at o -- asserted, not assumed."""
        insn = next(cs.disasm(buf[o:o + 6], va(o), count=1), None)
        if insn is None or insn.mnemonic != "je":
            found = f"'{insn.mnemonic} {insn.op_str}'" if insn else "nothing"
            raise LookupError(f"expected je at {va(o):#x}, found {found}")
        try:
            return int(insn.op_str, 0)
        except ValueError as e:
            raise LookupError(f"non-immediate je target at {va(o):#x}") from e

    return dict(
        parser_je=va(loc["parser"] + 16),    # the `je skip`
        proceed=va(loc["ac3"] + 27),         # past `mov eax,3`
        probe_site=va(loc["setup"] + 9),     # the `xor ebp,ebp` before frame-probe
        asc_parser=va(loc["asc"]),
        finalize=va(loc["finalize"]),
        dispatch=va(loc["dispatch"] + 4),              # `cmp eax,2` (past mov eax,[r15+8])
        ctor_arm=branch_target(loc["dispatch"] + 7),   # `je <ctor arm>` after cmp eax,2
    )


def build_patch_args(a, mkv_addrs=None, probe_addr=None, mkv=False,
                     probe_tag=1, probe_reg="r15"):
    """The e9tool -M/-P argument list for the additive patches."""
    b = TRAMPOLINE_BIN

    def R(reg, wanted, tgt):
        """`if redirect(reg, wanted, tgt) goto` -- the additive form: the
        trampoline returns tgt only when the register holds the AAC value, so
        for anything else the original instruction runs untouched."""
        return f"before if redirect({reg},{wanted:#x},{tgt:#x})@{b} goto"

    args = [
        "-M", f"addr={a['g1_site']:#x}",
        "-P", R(a["g1_reg"], AAC_FOURCC, a["g1_target"]),
        "-M", f"addr={a['a_site']:#x}",
        "-P", R("rcx", AAC_CODEC_ID, a["fetch"]),
        "-M", f"addr={a['b_site']:#x}",
        "-P", R("rdi", AAC_CODEC_ID, a["copy"]),
        "-M", f"addr={a['after_call']:#x}",
        "-P", f"before build5(rbx,{a['insert']:#x})@{b}",
        # gate4: esds->ASC in-place at the extradata COPY (replaces aacfix.so shim)
        "-M", f"addr={a['copy']:#x}",
        "-P", f"before aac_esds_fix(rsp)@{b}",
    ]
    if mkv:                          # MKV: un-drop AAC + parse CodecPrivate (ASC)
        m = mkv_addrs
        args += ["-M", f"addr={m['parser_je']:#x}",
                 "-P", f"before if mkv_undrop(rdx,&rax,{m['proceed']:#x})@{b} goto",
                 "-M", f"addr={m['probe_site']:#x}",
                 "-P", (f"before if mkv_asc(rsp,r12,{m['asc_parser']:#x},"
                        f"{m['finalize']:#x})@{b} goto"),
                 "-M", f"addr={m['dispatch']:#x}",
                 "-P", R("rax", 1, m["ctor_arm"])]
    if probe_addr is not None:
        # debug: log a tagged register value.  tools/mkvprobe.c declares
        # probe(long tag, long val), so both arguments must be passed -- the
        # tag lets several instrumented sites share one trampoline build.
        args += ["-M", f"addr={probe_addr:#x}",
                 "-P", f"before probe({probe_tag},{probe_reg})@{PROBE_BIN}"]
    return args


def apply(src, out, probe_addr=None, mkv=False, probe_tag=1, probe_reg="r15"):
    buf = open(src, "rb").read()
    em = ElfMap(src)
    a = resolve_addresses(buf, em)                 # raises if a site is missing
    mkv_addrs = resolve_mkv(buf, em) if mkv else None
    compile_trampoline()
    if probe_addr is not None:
        _e9compile(PROBE_SRC, PROBE_BIN)
    patch_args = build_patch_args(a, mkv_addrs, probe_addr, mkv,
                                  probe_tag, probe_reg)
    expected = sum(1 for x in patch_args if x == "-P")   # one patch per -P clause
    cmd = [E9TOOL] + patch_args + [src, "-o", out]
    res = subprocess.run(cmd, cwd=E9DIR, capture_output=True, text=True)
    if res.returncode == 0:
        # e9tool can decline a site (unpatchable instruction) and still exit 0.
        # Shipping a binary with only some gates installed is worse than
        # failing: a redirect can jump into a gate that was never installed.
        m = re.search(r"num_patched\s*=\s*(\d+)\s*/\s*(\d+)", res.stdout)
        if not m:
            raise RuntimeError("e9tool did not report num_patched; refusing")
        got, total = int(m.group(1)), int(m.group(2))
        if got != total or got != expected:
            if os.path.exists(out):
                os.remove(out)
            raise RuntimeError(
                f"e9tool patched {got}/{total} sites (expected {expected}); "
                "refusing to emit a partially-patched binary")
    return a, cmd, res


def main(argv):
    ap = argparse.ArgumentParser(prog="aacpatch.additive")
    ap.add_argument("binary")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--probe-mkv", type=lambda s: int(s, 0), default=None,
                    help="debug: log a register value at this vaddr "
                         "(see tools/mkvprobe.c; writes /tmp/mkvprobe.log)")
    ap.add_argument("--probe-tag", type=lambda s: int(s, 0), default=1,
                    help="tag for --probe-mkv, so several probe sites can "
                         "share one build (default 1)")
    ap.add_argument("--probe-reg", default="r15",
                    help="register --probe-mkv logs (default r15)")
    ap.add_argument("--mkv", action="store_true",
                    help="also apply the MKV AAC patches (parser un-drop, "
                         "CodecPrivate ASC parse, dispatch-redirect)")
    args = ap.parse_args(argv[1:])

    try:
        a, cmd, res = apply(args.binary, args.out,
                            probe_addr=args.probe_mkv, mkv=args.mkv,
                            probe_tag=args.probe_tag, probe_reg=args.probe_reg)
    except Exception as e:
        # locate/parse failure -> unknown/unsupported build (or bad input).
        # Refuse cleanly: never emit a partially-patched binary.
        kind = "cannot locate a patch site" if isinstance(e, LookupError) \
            else type(e).__name__
        print(f"error: {kind}: {e}")
        print("       (unsupported Resolve build or bad input; no output written)")
        return 1

    print("resolved addresses:")
    for k, v in a.items():
        print(f"  {k:12} {v:#x}" if isinstance(v, int) else f"  {k:12} {v}")
    print("\ne9tool:", " ".join(cmd[1:]))
    tail = [l for l in res.stdout.splitlines()
            if any(t in l for t in ("num_patched ", "error", "time_elapsed"))]
    print("\n".join(tail))
    if res.returncode != 0:
        print(res.stderr[-2000:])
        return 1
    print(f"\nwrote {args.out} ({os.path.getsize(args.out)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
