# Reverse-engineering notes

How AAC was removed from the Linux build of DaVinci Resolve Studio, and how each
removal was found and undone. Addresses are virtual addresses in **Resolve Studio
21.0.3** unless stated; every one of them is located at runtime by signature, so
treat them as landmarks for reading along, not as constants.

Companion documents: [`further-work.md`](further-work.md) for how to continue
this, [`tooling.md`](tooling.md) for the instruments, [`notes/`](notes/) for the
unedited session logs including the dead ends.

---

## 1. The target

```
/opt/resolve/bin/resolve
ELF64 EXEC, x86-64, non-PIE, stripped, 653,047,344 bytes
4 PT_LOAD segments
```

Two properties shape everything else.

**It is stripped and enormous.** No symbols, no debug info, 653 MB. A Ghidra
headless import was attempted and abandoned — see
[`further-work.md`](further-work.md#method-what-actually-worked). Everything here
was found with direct `.text` scanning, gdb, and differential coverage instead.

**Its LOAD segments do not share one delta.** Three segments map at
`vaddr = offset + 0x400000`; the last one uses `0x401000`:

```
  off 0x000000000  va 0x00000400000  sz 0x3743a0    R--  delta 0x400000
  off 0x000375000  va 0x00000775000  sz 0x93982a1   R-X  delta 0x400000
  off 0x00970e000  va 0x00009b0e000  sz 0x1d29a71c  R--  delta 0x400000
  off 0x0269a8740  va 0x00026da9740  sz 0x51c118    RW-  delta 0x401000
```

That last segment holds the vtables and typeinfo. An earlier generation of these
scripts assumed a single base and silently produced wrong addresses for every
class it reported — the results looked plausible and were not. `aacpatch/elfmap.py`
derives the deltas per segment from the program headers, and
`tests/test_elfmap.py` pins the behaviour.

## 2. Two independent gates

AAC is blocked in two places, and lifting either alone achieves nothing:

| | what | effect if you only fix this one |
|---|---|---|
| **the libraries** | `/opt/resolve/libs/libavcodec.so.60` has the AAC decoder compiled out | `bin/resolve` asks for a decoder that does not exist |
| **the binary** | `bin/resolve` never asks for AAC in the first place | a capable decoder sits there unused |

`aac-patch-tree status` reports them separately and warns about the half-installed
case, because "binary patched, libs not" fails silently as no audio.

### 2a. What Blackmagic did to the libraries

Every FFmpeg library embeds its configure line in the `--prefix` string. Reading it
out of the bundled `libavcodec` gives their build recipe verbatim:

```
--prefix=/media/datastore1/build/bmd-eng-ub_FTKZ/tmp/install/linux/
--enable-runtime-cpudetect --disable-lzma --disable-xlib --enable-shared
--disable-programs --disable-doc --disable-avdevice --disable-postproc
--disable-avfilter --disable-pixelutils --disable-static --disable-swresample
--disable-iconv
--disable-decoder='aac*' --disable-encoder='aac*,ac3*' --disable-parser='aac*'
--disable-muxer='aac*,ac3*' --disable-demuxer='aac*,ac3'
```

That settles a question worth settling: the strip is a **configure-time exclusion**,
nothing more. No source patching, no substituted decoder, no external codec
libraries, no `--enable-gpl`. Note too that only the AC-3 *encoder*, muxer and
demuxer were removed — the AC-3 **decoder** was left in, which is why AC-3 audio
plays today and why preserving it matters.

The fix is to rebuild the same FFmpeg with only the `ac3` halves of those five
flags. See [`ffmpeg-libs.md`](ffmpeg-libs.md).

### 2b. What Blackmagic did to the binary

This is the interesting half, and it is not one edit. Resolve has a separate
decoder class per container family, and AAC was removed from each one differently:

```
IOQuickTimeAudioDecoder   .mp4 .mov .m4a     4 removals   -- restored
IOMKVAudioDecoder         .mkv               3 removals   -- restored
IOADTSAudioDecoder        raw .aac           not analysed -- open
                          .ts .flv .latm     not analysed -- open
```

All of them funnel into one shared class, `IOAudioFFMPEGCodec`, whose constructor
at `0x5b56150` has **9 callers** (confirmed with
`tools/scan/callxref.py ctor=0x5b56150`). Two of the four QuickTime gates live
inside that shared constructor, so they are already fixed for every other
container — which is why the Matroska work needed only container-specific changes,
and why the still-open formats should need less than the first one did.

## 3. The QuickTime path (`.mp4` / `.mov` / `.m4a`)

Four removals, restored by five trampolines.

### gate 1 — the fourcc dispatch has no `aac ` case

`IOQuickTimeAudioDecoder` switches on the track's fourcc to pick a decoder
implementation. `.mp3`, `flac`, `alac`, `ac-3` and a `NONE` fallback are all
present; `aac ` is not.

```asm
0x5b61670   cmp r15d, '.mp3'        ; 41 81 ff 33 70 6d 2e
0x5b61677   je   0x5b6178c          ; -> IOAudioFFMPEGCodec handler
```

`.mp3` and `flac` both jump to the same handler, so AAC needs to reach exactly
that address. The signature anchors on the **`.mp3` comparison** rather than on
the AAC-shaped hole, and reads the handler address out of the `je` — which makes
it both version-independent and self-checking, since the target is derived rather
than assumed.

Which register holds the fourcc is the compiler's choice, and it does move
between point releases: `r15d` up to 21.1, `r12d` in 21.1.1
(`41 81 fc 33 70 6d 2e`). So the ModRM byte is wildcarded, capstone confirms the
hit is `cmp r8d..r15d, '.mp3'`, and the register it names is the one handed to
the trampoline.

The first working version of this patch instead repointed the `NONE` branch at
`aac `, which worked but cost the `NONE` fourcc. The trampoline form costs
nothing.

### gate 2 — the fourcc→AVCodecID table has no AAC row

A `std::map<u32,int>` built once at startup from a static 4-row table
(`0xa497f0c`, 8 bytes per row, `{fourcc_le, codec_id}`):

```
'alac' -> 0x15010     'flac' -> 0x1500c     '.mp3' -> 0x15001     'ac-3' -> 0x15003
```

AAC would be `0x15002`. The builder is at `0xcb2590`:

```asm
movups xmm0, [rip+...]        ; table[16:32]  (.mp3, ac-3 rows)
movaps [rsp+0x20], xmm0
movups xmm0, [rip+...]        ; table[0:16]   (alac, flac rows)
movaps [rsp+0x10], xmm0       ; 32-byte stack copy of the 4-row table
lea    rbx, [rip+...]         ; rbx = the map object
lea    rsi, [rsp+0x10]        ; rsi = &table
lea    rcx, [rsp+0xf]         ; DEAD -- insert_range never reads rcx
mov    edx, 4                 ; count
mov    rdi, rbx
call   0x5b57710              ; insert_range(map, table, count)
```

The decisive finding is in `insert_range` itself:

```
insert_range(rdi=map, rsi=table, rdx=count):
  [rdi+8 .. +0x18] = 0 ; [rdi] = rdi+8        <-- RE-INITIALISES the map
  if rdx == 0: return
  end = table + count*8                       <-- confirms 8-byte entries
  for e in table[0..count):
      walk red-black tree; alloc+link node (copies the 8 bytes)
      [map+0x10]++
```

It resets the map on entry. So the fix does not have to modify the table, the
count, or the register setup — it can simply **call the binary's own
`insert_range` a second time**, after the original call, with a 5-row table:

```c
static const struct entry TABLE5[5] = {
    {0x616c6163u, 0x15010u},  /* alac */
    {0x666c6163u, 0x1500cu},  /* flac */
    {0x2e6d7033u, 0x15001u},  /* .mp3 */
    {0x61632d33u, 0x15003u},  /* ac-3 */
    {0x61616320u, 0x15002u},  /* aac   <- added */
};
void build5(void *map, void *insert_range) {
    ((insert_range_t)insert_range)(map, TABLE5, 5);
}
```

The 4-entry build runs first and is then wholly replaced. `rbx` still holds the
map pointer at the after-call site because it is callee-saved. It leaks four
red-black-tree nodes once at startup, which is not worth caring about.

The earlier destructive version repointed the `ac-3` row at `aac `, which broke
AC-3 decode. That trade is gone.

### gate 3 — extradata is fetched and attached only for ALAC and FLAC

Inside the shared `IOAudioFFMPEGCodec` constructor
(`0x5b5679b`..`0x5b56973`), the codec config blob is handled as:

```
load codec_id
  ALAC or FLAC  -> FETCH   (virtual [rax+0x50] fills a stack blob at [rsp], [rsp+8])
  ALAC          -> cookie path
  FLAC          -> sub rdx,rsi ; cmp rdx,0x22 ; je COPY
```

Two `cmp` sites gate it (`cmp ecx,0x1500c` at `0x5b567a7`, `cmp edi,0x1500c` at
`0x5b56801`), and a size gate at `0x5b5680d` insists the blob is exactly 34 bytes
— an ALAC cookie constraint.

The finding that makes this cheap: **COPY (`0x5b5691f`) recomputes the length from
the stack (`[rsp+8] - [rsp]`), not from `rdx`.** So AAC can jump straight to COPY,
skipping the size gate entirely, and the copy is still correct. The size gate is
left completely untouched, so FLAC and ALAC behave exactly as before.

Two trampolines, both of the same additive shape:

```
0x5b567a7   if (ecx == AAC) goto FETCH  (0x5b567b3)
0x5b56801   if (edi == AAC) goto COPY   (0x5b5691f)
```

### gate 4 — `esds` where FFmpeg wants an `AudioSpecificConfig`

With gate 3 lifted, AAC reaches FFmpeg with extradata attached — and
`avcodec_open2` fails. Resolve hands over the **whole 41-byte MPEG-4 `esds`
descriptor**; FFmpeg's AAC decoder wants only the 4–5 byte `AudioSpecificConfig`
nested inside it.

This was first solved with an `LD_PRELOAD` shim that rewrote the extradata inside
`avcodec_open2`. That shim is gone: the same descriptor walk now runs as a
trampoline at the COPY site, so the config blob is trimmed to the ASC in place
before it is ever attached.

```c
void aac_esds_fix(long rsp) {
    unsigned char *start = *(unsigned char **)(rsp);
    unsigned char *end   = *(unsigned char **)(rsp + 8);
    long len = end - start;
    if (len > 5 && start[0] == 0x03) {          /* tag 0x03 == ES_Descr */
        int asc_len = 0;
        const unsigned char *asc = find_asc(start, (int)len, &asc_len);
        if (asc && asc_len > 0 && asc_len <= len) {
            for (int k = 0; k < asc_len; k++) start[k] = asc[k];  /* dst<src */
            *(unsigned char **)(rsp + 8) = start + asc_len;
        }
    }
}
```

ALAC and FLAC config blobs do not begin with `0x03`, so they pass through
untouched. Removing the shim also removed the launcher wrapper: **the patched
binary needs no `LD_PRELOAD` and no special launch path.** Run
`/opt/resolve/bin/resolve` normally.

One honest caveat, recorded in [`notes/PATCH_REVIEW.md`](notes/PATCH_REVIEW.md):
this is a **workaround, not a restoration**. Diffing against the macOS build shows
its gate 3 is byte-identical to Linux's and also handles only ALAC and FLAC —
macOS has a *separate* dedicated AAC extradata path (15 `cmp …,0x15002` sites in
its text, none near the shared constructor). Re-using the FLAC fetch/attach path
and then trimming the blob works for every case tested, but it is not how the
original code does it.

## 4. The Matroska path (`.mkv`)

Structurally different, and the part that took the longest.

### The parser recognises `A_AAC` and deliberately throws it away

```asm
0x5b5d3bb   mov edi, 'A_AA'
            ...
            xor edx, 'C'                ; combined compare
            or  ...
0x5b5d3cb   je  <skip-track loop>       ; <-- INVERTED
```

AC-3 and FLAC do the opposite: `jne skip`, then proceed and set a `codec_type`.
This branch matches `A_AAC` and jumps *to* the skip loop. It is the clearest
single piece of evidence in the binary that the removal was deliberate.

### `codec_type` 1 is still wired to `aac ` everywhere else

The MKV `getCodecInfo` at `0x5b601f0` maps `codec_type` through a jump table at
`0xa4988f8`:

```
1 -> "aac "     2 -> ".mp3"     3 -> "ac-3"     7 -> "flac"
```

So the packets source, the fourcc mapping, and everything downstream *already*
support AAC. Only the gates around them were stripped. That fixes the value the
un-drop must write: `codec_type = 1`, not a new invented type.

```c
void *mkv_undrop(long matched, long *rax, void *proceed) {
    if ((unsigned int)matched == 0) { *rax = 1; return proceed; }
    return 0;
}
```

### CodecPrivate is a raw ASC, and AAC must not be frame-probed

Un-dropping alone produces no audio. Routing AAC through AC-3's proceed path gets
the shared descriptor setup right but then hits AC-3's **frame probe**, which
rejects AAC.

The macOS binary answered this directly. Its AAC handler does *not* frame-probe:
it calls an **AudioSpecificConfig parser** on the MKV `CodecPrivate`
(`[r12+0x90]`) to fill the descriptor, then joins the common "add stream"
finalize. That ASC parser is still present in the Linux binary at `0x5b5d9f0` —
only its caller was removed. (Linux `0x5b5d71e` = macOS `0x102796e20` for the
finalize.)

```c
void *mkv_asc(long rsp, long r12, long asc_parser, long finalize) {
    if (*(const int *)(rsp + 0x38) != 1) return 0;      /* not AAC: AC-3 keeps probing */
    ((asc_parser_t)asc_parser)(0, r12 + 0x90, 0, 0, rsp + 0x30);
    /* HE-AAC: the parser writes the AAC *base* rate; SBR output is doubled. */
    long cp = *(const long *)(r12 + 0x90);
    if (cp) {
        int aot = *(const unsigned char *)cp >> 3;      /* audioObjectType */
        if (aot == 5 || aot == 29) *(int *)(rsp + 0x44) *= 2;   /* SBR / PS */
    }
    return (void *)finalize;
}
```

The SBR sample-rate doubling only handles **explicit** signalling. Implicit SBR
(base AOT 2, SBR detected by the decoder) and the AOT=31 escape (real type =
32 + next 6 bits) report the base rate. Neither appeared in the verified set; the
place to extend is right there.

### A type-1 arm in the codec dispatch

`F` — the per-track decoder function — dispatches on `codec_type`:

```asm
0x5b5e339   mov eax, [r15+8]
0x5b5e33d   cmp eax, 2 ; je <ctor arm 0x5b5e493>
            cmp eax, 3 ; je ...
            cmp eax, 7 ; ...
```

Types 2/3/7 route to the `IOAudioFFMPEGCodec` constructor; type 1 has no arm.
One more `redirect(rax, 1, ctor_arm)` and MKV joins the shared path, where gates
2, 3 and 4 finish the job.

Verified: `find_decoder(id=86018 aac) -> aac`, `open2(aac ch=2 sr=48000) -> 0`,
audio plays.

### Audio-only MKV is silent — and that is Resolve's bug, not this patch's

An MKV containing only an audio track plays no audio in Resolve **for any codec**.
This reproduces with native FLAC, AC-3 and MP3 audio-only MKVs, which Resolve
supports and which this patch does not go near. Decode is correct; nothing comes
out. MKV *with* a video track works. `tools/make-testdata.sh` generates
`ao_flac.mkv` / `ao_ac3.mkv` / `ao_mp3.mkv` precisely so this can be re-confirmed
in ten seconds rather than re-debugged.

## 5. Why additive, and why e9patch

Every change above is expressed as: *if the value is AAC, jump somewhere; otherwise
return 0 and let the original instruction run.* No existing instruction is
rewritten. `NONE`, AC-3, FLAC, ALAC, MP3, PCM and the AV3A demuxer are all
untouched by construction, and `uninstall` restores the original byte-for-byte.

That constraint is not aesthetic. The broadest published evaluation of x86-64
binary rewriters ([Schulte, Brown & Folts, CSET 2022](https://doi.org/10.1145/3546096.3546112))
found that trampoline rewriters such as e9patch are

> "very reliable across a wide range of binaries **if only additive
> instrumentation and no modification of existing code is required**"

and this target is close to that study's worst case: 653 MB, stripped, non-PIE, no
relocation information. Tools that rewrite existing code (ddisasm, Zipr) were
impractical here on both counts — their memory use is super-linear, and modifying
existing code is the study's flagged reliability killer. e9patch rewrites the whole
653 MB binary in ~3.2 s using ~10 MB of RSS.

**One mechanical detail worth knowing.** e9patch does not edit bytes at the patch
site. It leaves the original image intact and **remaps the patched 4 KB pages at
load time** via added program headers, appending a 5th LOAD segment for the
trampolines. Two consequences:

- Any static byte edits must be applied **first**, then e9patch run on the result —
  otherwise they are not in the pages e9patch copied.
- "Does this binary have more than 4 LOAD segments" is a reliable, marker-free
  test for "is it patched", which is what `aac-patch-tree` uses.

## 6. Site table

Every address is found by a byte signature at run time
(`aacpatch/sites.py`); this table just shows that they really do move between
point releases, and that nothing here is hardcoded.

| site | 21.0.3 | 21.0.4 | what it is |
|---|---|---|---|
| `g1_site` | `0x5b61670` | `0x5b6a280` | the `.mp3` fourcc compare (anchor) |
| `g1_target` | `0x5b6178c` | `0x5b6a39c` | the FFmpeg codec handler, read from its `je` |
| `after_call` | `0xcb25dc` | `0xcb27ec` | just past `call insert_range` |
| `insert` | `0x5b57710` | `0x5b60320` | `insert_range(map, table, count)` |
| `a_site` | `0x5b567a7` | `0x5b5f3b7` | gate 3a, `cmp ecx, FLAC` |
| `fetch` | `0x5b567b3` | `0x5b5f3c3` | the extradata FETCH path |
| `b_site` | `0x5b56801` | `0x5b5f411` | gate 3b, `cmp edi, FLAC` |
| `copy` | `0x5b5691f` | `0x5b5f52f` | the extradata COPY (also the gate-4 site) |
| `parser_je` | `0x5b5d3cb` | `0x5b65fdb` | the inverted `A_AAC` branch |
| `proceed` | `0x5b5d4f0` | `0x5b66100` | shared setup proceed path |
| `probe_site` | `0x5b5d525` | `0x5b66135` | just before AC-3's frame probe |
| `asc_parser` | `0x5b5d9f0` | `0x5b66600` | the orphaned ASC parser |
| `finalize` | `0x5b5d71e` | `0x5b6632e` | shared "add stream" finalize |
| `dispatch` | `0x5b5e33d` | `0x5b66f4d` | F's `cmp eax,2` codec-type dispatch |
| `ctor_arm` | `0x5b5e493` | `0x5b670a3` | the FFmpeg ctor arm, read from its `je` |

Regenerate for any build:

```sh
python -m aacpatch.locate /opt/resolve/bin/resolve.aac-orig
```

Signatures key only on bytes the patch never touches — opcodes, fourcc constants,
the `0x1500x` codec IDs, the table entry count — and wildcard exactly the bytes
that shift between builds (RIP-relative displacements, branch rel32s, absolute
pointers). Two properties follow: a signature locates its site whether the binary
is pristine or already patched, and **more than one match is an error**, never
"take the first". A build we do not understand must stop the tool, not be guessed
at.

## 7. What still does not work

| format | status |
|---|---|
| `.mp4` `.mov` `.m4a` | works — LC and HE-AAC |
| `.mkv` with a video track | works — LC and HE-AAC |
| `.mkv` audio-only | silent — pre-existing Resolve bug, see §4 |
| raw `.aac` (ADTS) | not done — `IOADTSAudioDecoder` not analysed |
| `.ts` `.flv` `.latm` | not done |
| MXF | not investigated; ffmpeg cannot even mux AAC into MXF without a video stream, and Resolve's MXF audio is normally PCM |

The open ones are scoped in [`further-work.md`](further-work.md).
