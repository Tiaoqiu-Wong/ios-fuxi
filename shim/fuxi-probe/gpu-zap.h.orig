/* Qualcomm PAS13, Linux6.12 mdt_loader + qcom_scm ARM64 ABI.
 * Included after gpu_m4. All input remains in the optional, external MBN.
 * No WAITQ, interrupted-call continuation or TRUST MMIO writes. XNU permits
 * one bounded retry ONLY for the unserviced x0 == original function ID case.
 */
#define G5_META_PA (G_MEM + 0x1600000)
#define G5_META_BYTES 0x2000u
#define G5_ZAP_PA 0x9b09a000ULL /* sm8550.dtsi AND Fuxi live DT, no-map */
#define G5_ZAP_BYTES 0x2000u
#define G5_PAS 13u
#define G5_SMC(cmd) (0x42000200u | (cmd)) /* STD, SMC64, owner SIP, PIL */
_Static_assert((G5_META_PA & 4095) == 0, "PAS metadata alignment");
_Static_assert(G5_META_PA >= G4_DST_PA + G4_BYTES + 4096, "PAS metadata overlaps 2D");
_Static_assert(G5_META_PA + G5_META_BYTES <= G_MEM + G_MEM_SIZE, "PAS metadata overflow");
static unsigned g5_zap_loaded; /* only OUR successful auth, never inferred from TZ */
struct g5_plan {
 unsigned phoff, phnum, header, hash_off, hash_size, relocate, loads;
 uint64_t min, max, base;
};
/* No pointer casts to potentially unaligned ELF structs, no 32-bit additions
 * until both ends have been checked in 64 bits. Single-file ELF32 LE only. */
static int g5_plan_mbn(const uint8_t *fw, size_t bytes, struct g5_plan *p)
{
 if (bytes < 52 || bytes > 0x10000 || cdb32(fw) != 0x464c457f ||
     fw[4] != 1 || fw[5] != 1 || fw[6] != 1 || cdb16(fw+16) != 2 ||
     cdb16(fw+18) != 0xa4 || cdb32(fw+20) != 1 ||
     cdb16(fw+40) != 52 || cdb16(fw+42) != 32 ||
     cdb16(fw+46) || cdb16(fw+48)) return 0xf03;
 p->phoff = cdb32(fw+28); p->phnum = cdb16(fw+44);
 if (p->phnum < 2 || p->phnum > 64 || p->phoff < 52 ||
     (uint64_t)p->phoff + p->phnum*32u > bytes) return 0xf03;
 const uint8_t *ph = fw+p->phoff;
 p->header = cdb32(ph+16); p->hash_size = p->loads = p->relocate = 0;
 p->min = ~0ULL; p->max = 0;
 if (cdb32(ph) == 1 || p->header < p->phoff+p->phnum*32u || p->header > bytes) return 0xf03;
 for (unsigned i = 0; i < p->phnum; i++) {
  ph = fw+p->phoff+i*32u;
  unsigned flags = cdb32(ph+24), file = cdb32(ph+16), mem = cdb32(ph+20);
  uint64_t off = cdb32(ph+4), pa = cdb32(ph+12);
  if (file && off+file > bytes) return 0xf04; /* no split-file fallback */
  if ((flags & 0x07000000u) == 0x02000000u) {
   if (!i || p->hash_size || !file) return 0xf03;
   p->hash_off = off; p->hash_size = file;
   continue;
  }
  if (cdb32(ph) != 1 || !mem) continue;
  if (file > mem || ((pa | file | mem) & 3u)) return 0xf04;
  p->loads++; p->relocate |= !!(flags & (1u<<27));
  if (pa < p->min) p->min = pa;
  uint64_t end = (pa+mem+4095u) & ~4095ULL;
  if (end > p->max) p->max = end;
 }
 if (!p->loads || !p->hash_size || p->header+p->hash_size > G5_META_BYTES ||
     ((p->header | p->hash_size) & 3u)) return 0xf04;
 p->base = p->relocate ? p->min : G5_ZAP_PA;
 /* adreno allocates qcom_mdt_get_size(), not the whole reserved region. */
 if (p->max <= p->min || p->max > 0xffffffffULL || p->max-p->min > G5_ZAP_BYTES) return 0xf04;
 for (unsigned i = 0; i < p->phnum; i++) {
  ph = fw+p->phoff+i*32u;
  if (cdb32(ph) != 1 || !cdb32(ph+20) ||
      (cdb32(ph+24) & 0x07000000u) == 0x02000000u) continue;
  uint64_t pa = cdb32(ph+12), end = pa+cdb32(ph+20);
  if (pa < p->base || end-p->base > p->max-p->min) return 0xf04;
  /* Refuse overlapping LOADs before the first SCM or reserved-memory write. */
  for (unsigned j = 0; j < i; j++) {
   const uint8_t *q = fw+p->phoff+j*32u;
   if (cdb32(q) == 1 && cdb32(q+20) &&
       (cdb32(q+24) & 0x07000000u) != 0x02000000u &&
       pa < (uint64_t)cdb32(q+12)+cdb32(q+20) && cdb32(q+12) < end) return 0xf04;
  }
 }
 return 0;
}
/* SMCCC x0 transport status, x1 service result, x2/x3 extra results.
 * x6 starts at zero (QCOM_A6); nonzero x0 stops, including interrupted=1,
 * WAITQ_SLEEP=2 and EBUSY=-12. There is deliberately no call continuation. */
static __attribute__((noinline)) void g5_smc_raw(uint64_t ret[4], uint32_t fn, uint32_t info,
                       uint64_t a, uint64_t b, uint64_t c)
{
 register uint64_t x0 __asm__("x0") = fn, x1 __asm__("x1") = info;
 register uint64_t x2 __asm__("x2") = a, x3 __asm__("x3") = b;
 register uint64_t x4 __asm__("x4") = c, x5 __asm__("x5") = 0;
 register uint64_t x6 __asm__("x6") = 0, x7 __asm__("x7") = 0;
 /* Darwin's AArch64 assembler treats ';' as a comment, unlike ELF GAS.
  * Separate instructions with newlines or the entire SMC silently vanishes. */
 __asm__ volatile("dsb sy\n\tsmc #0\n\tdsb sy"
  : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
  :: "x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
 ret[0] = x0; ret[1] = x1; ret[2] = x2; ret[3] = x3;
}
/* Eight fixed slots, including in-flight markers for a non-returning SMC.
 * First five retain the v8 layout; last three use v9 page15 words16..63.
 * Each slot: step, fn, arginfo, returned, arg0/arg1 low/high, x0..x3 low/high.
 * mem_setup arg2 is the validated span in page word16. */
static uint32_t *g5_scm_slot(uint32_t *d, unsigned i)
{
 return i < 5 ? d+48+16*i : gpu_extra[14]+16+16*(i-5);
}
static int g5_scm(uint32_t *d, uint32_t fn, unsigned info,
                   uint64_t a, uint64_t b, uint64_t c, unsigned advisory)
{
 if (d[5] >= 8) return 0;
 uint32_t *s = g5_scm_slot(d, d[5]++);
 s[0] = d[3]; s[1] = fn; s[2] = info;
 s[4] = a; s[5] = a>>32; s[6] = b; s[7] = b>>32;
 __asm__ volatile("dsb sy" ::: "memory");
 uint64_t ret[4];
#ifdef FUXI_GPU_XNU
 fg_scm_call(ret, d[5]-1, d[3], fn, info, a, b, c);
#else
 g5_smc_raw(ret, fn, info, a, b, c);
#endif
 for (unsigned i = 0; i < 4; i++) { s[8+i*2] = ret[i]; s[9+i*2] = ret[i]>>32; }
 s[3] = 1;
 /* Query x1 is a boolean, not a service status. Record even false/unknown;
  * only transport errors stop queries. Real PAS calls require x0=x1=0. */
 int ok = !ret[0] && (advisory || !ret[1]);
 if (!ok) d[44] = d[5];
 return ok;
}
/* Aligned CPU copies with abort-contained stores AND full readback. Metadata
 * pages are dedicated, uncached, contiguous, and kept untouched after init. */
static int g5_copy(uint64_t dst, const uint8_t *src, unsigned bytes)
{
 for (unsigned off = 0; off < bytes; off += 4)
  if (!g3_write(dst+off, src ? cdb32(src+off) : 0)) return 0;
 for (unsigned off = 0; off < bytes; off += 4)
  if (g3_read(dst+off) != (src ? cdb32(src+off) : 0) || gpu_extra[5][116]) return 0;
 return 1;
}
static int g5_pas(uint32_t *d, const uint8_t *fw, const struct g5_plan *p)
{
 /* The monitor never collapses GX or re-enters this after success. Retain the
  * Linux remote-state ABI for a caller that already owns an authenticated zap;
  * NEVER guess it is loaded from TRUST, support queries or failed cold auth. */
 if (g5_zap_loaded) {
  d[38] = 2;
  return g5_scm(d, 0x4200010a, 2, 0, G5_PAS, 0, 0) ? 1 : 0xf10;
 }
 d[38] = 1; d[3] = 3;
 if (!g5_scm(d, 0x42000601, 1, 0x02000207, 0, 0, 1)) return 0xf05;
 d[3] = 4;
 if (!g5_scm(d, G5_SMC(7), 1, G5_PAS, 0, 0, 1)) return 0xf06;
 d[3] = 5;
 if (!g5_scm(d, 0x42000601, 1, 0x02000201, 0, 0, 1)) return 0xf05;
 if (!g5_copy(G5_META_PA, 0, G5_META_BYTES) ||
     !g5_copy(G5_META_PA, fw, p->header) ||
     !g5_copy(G5_META_PA+p->header, fw+p->hash_off, p->hash_size)) return 0xf09;
 if (!g5_scm(d, G5_SMC(1), 0x82, G5_PAS, G5_META_PA, 0, 0)) return 0xf07;
 d[3] = 6;
 /* Linux qcom_mdt_pas_init: any valid relocatable LOAD enables setup;
  * args are reserved base and ALIGN(max end,4K)-min paddr, not reservation size. */
 if (p->relocate) {
  if (!g5_scm(d, 0x42000601, 1, 0x02000202, 0, 0, 1)) return 0xf05;
  if (!g5_scm(d, G5_SMC(2), 3, G5_PAS, G5_ZAP_PA, p->max-p->min, 0)) return 0xf08;
 }
 d[3] = 7;
 for (unsigned i = 0; i < p->phnum; i++) {
  const uint8_t *ph = fw+p->phoff+i*32u;
  unsigned file = cdb32(ph+16), mem = cdb32(ph+20);
  if (cdb32(ph) != 1 || !mem || (cdb32(ph+24) & 0x07000000u) == 0x02000000u) continue;
  uint64_t pa = G5_ZAP_PA+cdb32(ph+12)-p->base;
  if (!g5_copy(pa, file ? fw+cdb32(ph+4) : 0, file) || !g5_copy(pa+file, 0, mem-file)) return 0xf09;
  d[17] += file; d[18] += mem-file;
 }
 d[3] = 8;
 if (!g5_scm(d, 0x42000601, 1, 0x02000205, 0, 0, 1)) return 0xf05;
 if (!g5_scm(d, G5_SMC(5), 1, G5_PAS, 0, 0, 0)) return 0xf0a;
 g5_zap_loaded = d[4] = 1;
 return 1;
}
static int g5_run(uint32_t *d)
{
#if defined(FUXI_GPU_XNU)
 unsigned count;
 const uint8_t *fw = fg_firmware(2, &count);
 size_t bytes = count;
#elif defined(FUXI_XNU_LOADER)
 extern const uint8_t _zap_fw_start[], _zap_fw_end[];
 const uint8_t *fw = _zap_fw_start;
 size_t bytes = (uintptr_t)_zap_fw_end-(uintptr_t)_zap_fw_start;
#else
 const uint8_t *fw = 0; size_t bytes = 0;
#endif
 d[3] = 1; d[6] = bytes; d[8] = (uint32_t)G5_META_PA; d[9] = G5_META_PA>>32;
 d[10] = G5_ZAP_PA; d[11] = G5_ZAP_BYTES;
 if (gpu_extra[11][1] || gpu_extra[12][1]) return 0xf0f;
 d[25] = g3_gr(0x806); d[26] = g3_gr(0x807);
 d[31] = g3_gr(0x210);
 d[19] = g3_gr(0xf400); d[21] = g3_gr(0xfc00); d[22] = g3_gr(0xfc01);
 d[41] = g3_read(G3_FENCE_PA+4); d[42] = g3_read(G3_FENCE_PA+0xffc);
 if (gpu_extra[5][116]) return 0xf0b;
 if (g3_faulted()) return gpu_extra[5][116] ? 0xf0b : 0xf0c;
 if (gpu_extra[5][3] != 1 || gpu_extra[5][4] != 1 || !gpu_extra[5][7] ||
     d[25] != g3_wptr || d[26] != g3_wptr || g3_wptr != G3_FENCE_DWORDS ||
     (d[31] & ~1u) || d[41] != G3_GUARD || d[42] != G3_GUARD) return 0xf01;
 if (!bytes) return 0xf02;
 d[3] = 2;
 struct g5_plan plan = {0}; int err = g5_plan_mbn(fw, bytes, &plan);
 if (err) return err;
 d[7] = plan.header+plan.hash_size; d[12] = plan.min; d[13] = plan.max;
 d[14] = plan.relocate; d[15] = plan.loads; d[16] = plan.max-plan.min;
 err = g5_pas(d, fw, &plan); if (err != 1) return err;
 d[3] = 9;
 /* Linux hw_init: ONLY SET_SECURE_MODE(0), a6xx_flush (mb + doorbell),
  * a6xx_idle. Flush here means ring publication, not a guessed cache event. */
 if (gpu_extra[5][116]) return 0xf0b;
 if (g3_faulted()) return gpu_extra[5][116] ? 0xf0b : 0xf0c;
 d[28] = g3_gr(0x806); d[29] = g3_gr(0x807); d[31] = g3_gr(0x210);
 if (gpu_extra[5][116]) return 0xf0b;
 if (g3_wptr+2 >= 0x8000/4 || d[28] != g3_wptr ||
     d[29] != g3_wptr || (d[31] & ~1u)) return 0xf01;
 g3_emit(g3_pkt7(0x66, 1)); g3_emit(0);
 d[39] = g_rd(G3_RING_PA, (g3_wptr-2)*4); d[40] = g_rd(G3_RING_PA, (g3_wptr-1)*4);
 d[27] = g3_wptr;
 __asm__ volatile("dsb sy" ::: "memory");
 if (!g3_gw(0x807, g3_wptr)) return 0xf0b;
 d[43] = 1; d[3] = 10;
 for (unsigned i = 0; i < 5000; i++) {
  d[30] = i+1; d[28] = g3_gr(0x806); d[29] = g3_gr(0x807); d[31] = g3_gr(0x210);
  if (gpu_extra[5][116]) return 0xf0b;
  if (!(i & 15) && g3_faulted()) return gpu_extra[5][116] ? 0xf0b : 0xf0c;
  if (d[28] == g3_wptr && d[29] == g3_wptr && !(d[31] & ~1u)) break;
  if (i == 4999) return 0xf0d;
  delay(10);
 }
 d[3] = 11;
 d[20] = g3_gr(0xf400); d[23] = g3_gr(0xfc00); d[24] = g3_gr(0xfc01);
 d[32] = g3_gr(0x823); d[46] = g3_gr(0x821); d[47] = g3_gr(0x201);
 if (gpu_extra[5][116]) return 0xf0b;
 if (g3_faulted()) return gpu_extra[5][116] ? 0xf0b : 0xf0c;
 if (d[20]) return 0xf0e;
 if (g3_read(G3_FENCE_PA+4) != G3_GUARD || g3_read(G3_FENCE_PA+0xffc) != G3_GUARD) return 0xf01;
 if (gpu_extra[5][116]) return 0xf0b;
 d[3] = 12; gpu_m4(14); d[37] = gpu_extra[11][2]; g_enter(16);
 if (d[37] != 1) return d[37];
 d[3] = 13; return 1;
}
static void gpu_m5(void)
{
 uint32_t *d = gpu_extra[13];
 if (d[1]) return; /* includes failure: never retry or resume on a report read */
 g_enter(16); d[0] = 0xa7400009; d[1] = 16;
 gpu_extra[14][0] = 0xa7400009; gpu_extra[14][1] = 16;
 d[2] = g5_run(d);
 /* Retain raw CP errors even when packet waiting stopped before SECVID.
  * GX/OOB were proved by13 and are never released. No diagnostic clears. */
 if (d[43]) {
  d[32] = g3_gr(0x823); d[45] = g3_gr(0x824);
  d[46] = g3_gr(0x821); d[47] = g3_gr(0x201);
  if (d[2] == 1 && gpu_extra[5][116]) d[2] = 0xf0b;
  if (d[2] == 1 && g3_faulted()) d[2] = gpu_extra[5][116] ? 0xf0b : 0xf0c;
 }
 d[33] = gpu_extra[5][116]; d[34] = gpu_extra[5][110];
 d[35] = gpu_extra[5][111]; d[36] = gpu_extra[5][112];
}
