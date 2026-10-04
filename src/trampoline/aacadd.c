/*
 * Additive AAC support for DaVinci Resolve -- e9patch trampolines.
 *
 * Every change here is PURELY ADDITIVE: it only acts when the value is AAC and
 * otherwise returns 0 so the original instruction runs unchanged.  Nothing
 * upstream (NONE fourcc, AC-3, FLAC, ALAC, PCM, ...) is altered.
 *
 * Used with e9tool's `if CALL goto` form, i.e.  if (a = redirect(...)) goto a;
 *
 *   redirect(val, wanted, target):
 *       gate1  : if fourcc reg == 'aac '(0x61616320) -> FFmpeg-codec handler
 *                (r15 up to 21.1, r12 in 21.1.1: read off each build)
 *       gate3a : if codec_id ecx == AAC(0x15002)      -> extradata FETCH
 *       gate3b : if codec_id edi == AAC(0x15002)      -> extradata COPY (skips
 *                the 34-byte ALAC size gate; COPY reads the blob from the stack)
 *
 *   build5(map, insert_range):
 *       gate2  : rebuild the fourcc->AVCodecID map with 5 entries (adds AAC,
 *                keeps AC-3).  insert_range() re-inits the map, so calling it
 *                once more with a 5-row table fully replaces the 4-row build.
 *
 * All targets/addresses are resolved per build by the Phase-1 signature engine
 * and passed in as arguments, so nothing here is version-specific.
 *
 *   (compiled with e9compile.sh; see aacpatch/additive.py for the e9tool wiring)
 */

#include "stdlib.c"

/*
 * Additive redirect.  Returns `target` (non-NULL -> e9tool takes the goto) iff
 * the low 32 bits of `val` equal `wanted`; otherwise 0 (fall through to the
 * original instruction).  Comparison is 32-bit to match the binary's `cmp
 * r/m32, imm32` dispatch/codec tests.
 */
void *redirect(unsigned long val, unsigned long wanted, void *target)
{
    return ((unsigned int)val == (unsigned int)wanted) ? target : (void *)0;
}

/* --- gate 2: 5-entry fourcc->AVCodecID table ---------------------------- */

struct entry { unsigned int fourcc; unsigned int codec_id; };

static const struct entry TABLE5[5] =
{
    { 0x616c6163u, 0x15010u },  /* alac -> ALAC */
    { 0x666c6163u, 0x1500cu },  /* flac -> FLAC */
    { 0x2e6d7033u, 0x15001u },  /* .mp3 -> MP3  */
    { 0x61632d33u, 0x15003u },  /* ac-3 -> AC3  */
    { 0x61616320u, 0x15002u },  /* aac  -> AAC  (added) */
};

typedef void (*insert_range_t)(void *map, const void *table, long count);

void build5(void *map, void *insert_range)
{
    ((insert_range_t)insert_range)(map, TABLE5, 5);
}

/* --- esds -> ASC in-binary (replaces the aacfix.so LD_PRELOAD shim) ------ */

/*
 * Walk MPEG-4 descriptors, return the DecSpecificInfo (tag 0x05) payload.
 *
 * SECURITY: this parses metadata straight out of an untrusted media file, so
 * every bound is checked and all offset arithmetic uses `long`.  Bounds are
 * written as `len > n - i` (never `i + len > n`), because the latter overflows
 * for large i/len and wrongly reports "in bounds" -- with a ~2GiB blob that let
 * a crafted file walk far past the buffer and leak adjacent heap.
 */
static const unsigned char *find_asc(const unsigned char *p, long n, long *out_len)
{
    long i = 0;
    while (i < n) {
        long tag = p[i++], len = 0, cnt = 0, b;
        do { if (i >= n) return (void *)0; b = p[i++];
             len = (len << 7) | (b & 0x7f); } while ((b & 0x80) && ++cnt < 4);
        if (len < 0 || len > n - i) return (void *)0;      /* overflow-safe */
        if (tag == 0x05) { *out_len = len; return p + i; }
        if (tag == 0x03) {                 /* ES_Descr: skip ES_ID+flags, descend */
            if (n - i < 3) return (void *)0;
            long flags = p[i + 2], skip = 3;
            if (flags & 0x80) skip += 2;
            if (flags & 0x40) { if (skip >= n - i) return (void *)0;
                                skip += 1 + p[i + skip]; }
            if (flags & 0x20) skip += 2;
            if (skip > n - i) return (void *)0;
            i += skip; continue;
        }
        if (tag == 0x04) {                        /* DecoderConfigDescr: descend */
            if (n - i < 13) return (void *)0;
            i += 13; continue;
        }
        i += len;
    }
    return (void *)0;
}

/*
 * Is this blob a well-formed MPEG-4 esds (ES_Descr, tag 0x03) whose declared
 * length covers the rest of the buffer?  Checking the structure -- not just a
 * 0x03 first byte -- keeps us off ALAC/FLAC/other config blobs that merely
 * happen to start with 0x03, which we would otherwise truncate.
 */
static int looks_like_esds(const unsigned char *p, long n)
{
    long i = 1, len = 0, cnt = 0, b;
    if (n < 2 || p[0] != 0x03) return 0;
    do { if (i >= n) return 0; b = p[i++];
         len = (len << 7) | (b & 0x7f); } while ((b & 0x80) && ++cnt < 4);
    /* The declared body must fit in the blob.  Deliberately NOT requiring it to
       fill the blob exactly: an encoder that pads the esds would then be
       rejected and lose audio, and losing AAC on a valid file is worse than the
       (very unlikely) alternative.  The real discriminator is that find_asc must
       still walk this as a descriptor chain and reach a DecSpecificInfo. */
    return len > 0 && len <= n - i;
}

/*
 * gate 4 (in-binary).  At the IOAudioFFMPEGCodec extradata COPY, the config blob
 * is [rsp]..[rsp+8] and is copied verbatim into the codec extradata.  For AAC it
 * is a whole MPEG-4 esds (starts with tag 0x03) but FFmpeg wants just the ASC
 * (DecSpecificInfo).  Placed before the COPY: if the blob is an esds, move the
 * ASC to the buffer start in place and shorten [rsp+8] so COPY attaches only the
 * ASC.  (ALAC/FLAC configs don't start with 0x03, so they pass through.)  This
 * replaces the aacfix.so LD_PRELOAD shim -> pure binary patch.
 */
void aac_esds_fix(long rsp)
{
    unsigned char *start = *(unsigned char **)(rsp);
    unsigned char *end = *(unsigned char **)(rsp + 8);
    long len, asc_len = 0;
    const unsigned char *asc;

    if (!start || !end || end < start) return;
    len = end - start;
    if (len < 6 || !looks_like_esds(start, len)) return;   /* not an esds */

    asc = find_asc(start, len, &asc_len);
    /* asc must point inside [start, end) and the payload must fit from there */
    if (!asc || asc_len <= 0 || asc < start || asc >= end ||
        asc_len > end - asc) return;

    {
        long k;
        for (k = 0; k < asc_len; k++) start[k] = asc[k];   /* dst<src: safe */
        *(unsigned char **)(rsp + 8) = start + asc_len;
    }
}

/* --- MKV: restore AAC (removed only at the parser) ---------------------- */

/*
 * gate MKV-1 (parser un-drop).  The MKV CodecID parser recognises "A_AAC" and
 * deliberately jumps to the skip-track loop.  Placed before that `je`:
 * `matched`==0 means the CodecID equalled "A_AAC" (the branch's combined XOR).
 * On a match we set the codec_type (rax) to 1 -- the value the rest of the MKV
 * pipeline already maps to the "aac " fourcc (getCodecInfo) -- and redirect to
 * the shared proceed path (past its `mov eax,3`).  On no-match we return 0 so
 * the original `je` runs unchanged.
 */
void *mkv_undrop(long matched, long *rax, void *proceed)
{
    if ((unsigned int)matched == 0) { *rax = 1; return proceed; }
    return (void *)0;
}

/*
 * gate MKV (the REAL fix, from the Mac binary diff).  Mac's MKV AAC handler
 * sets codec_type=1 then parses the CodecPrivate AudioSpecificConfig via an ASC
 * parser and joins the common "add stream" finalize -- it does NOT frame-probe
 * like AC3.  Linux removed that handler (the parser `je` was repointed to skip)
 * but kept the ASC parser.  The un-drop routes AAC through AC3's proceed path,
 * which does the (correct, shared) descriptor setup but then frame-probes.
 * Placed just before the frame-probe loop: for AAC (codec_type at [rsp+0x38]==1)
 * call the ASC parser (rsi=&CodecPrivate at [r12+0x90], r8=&descriptor at
 * [rsp+0x30]) and redirect to the finalize; otherwise return 0 so AC3 keeps
 * frame-probing.  Addresses (asc_parser, finalize) are passed in per build.
 */
typedef void (*asc_parser_t)(long, long, long, long, long);

void *mkv_asc(long rsp, long r12, long asc_parser, long finalize)
{
    if (*(const int *)(rsp + 0x38) != 1) return (void *)0;   /* not AAC */
    ((asc_parser_t)asc_parser)(0, r12 + 0x90, 0, 0, rsp + 0x30);

    /*
     * HE-AAC (SBR) fix.  The ASC parser fills the descriptor sample rate (at
     * descriptor+0x14 == rsp+0x44) with the AAC *base* frequency.  For SBR the
     * decoder output is doubled, and the container/QuickTime path reports that
     * doubled rate -- so mirror it here.  audioObjectType is the top 5 bits of
     * the CodecPrivate: 5 = SBR (HE-AAC), 29 = PS (HE-AACv2).
     *
     * Limitation: only *explicit* SBR/PS signalling is handled.  Implicit SBR
     * (base AOT 2 with SBR detected by the decoder) and the AOT=31 escape
     * (real type = 32 + next 6 bits) are not doubled; such streams would report
     * the base rate.  Not seen in the verified set; extend here if needed.
     */
    {
        /* CodecPrivate is a {start,end} pair -- the same pair the ASC parser
           itself reads as [rsi]/[rsi+8].  Require at least one real byte before
           dereferencing: an A_AAC track with an EMPTY CodecPrivate is trivially
           craftable and would otherwise be a 1-byte heap over-read. */
        const unsigned char *cp  = *(const unsigned char **)(r12 + 0x90);
        const unsigned char *cpe = *(const unsigned char **)(r12 + 0x98);
        if (cp && cpe && cpe - cp >= 1) {
            int aot = cp[0] >> 3;
            if (aot == 5 || aot == 29)
                *(int *)(rsp + 0x44) *= 2;
        }
    }
    return (void *)finalize;
}
