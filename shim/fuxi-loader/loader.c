/* Fuxi XNU handoff: bounded embedded payload, upper RAM and measured splash.
 * No storage access. Only the CPU used by ABL is started.
 */
#include <stdint.h>
#include "console.h"
#include "../fuxi-probe/monitor.h"
#include "../fuxi-probe/gpu-handoff.h"
void probe_main(uintptr_t fdt);
uint64_t probe_fdt_address(void);
uint32_t probe_fdt_bytes(void);

#define BOOT_LINE_LENGTH	608
#define PAGE_16K		0x4000UL

struct payload_seg {
	uint64_t vmaddr, vmsize, file_off, file_size;
};

struct payload {
	char magic[8];
	uint32_t version, nsegs;
	uint64_t virt_base, entry_va, adt_off, adt_size, kernel_end;
	uint64_t phys_base, mem_size;
	char cmdline[BOOT_LINE_LENGTH];
	struct payload_seg segs[];
};

/* pexpert/pexpert/arm64/boot.h, Revision/Version 2 */
struct boot_video {
	uint64_t v_baseAddr, v_display, v_rowBytes, v_width, v_height, v_depth;
};

struct boot_args {
	uint16_t Revision, Version;
	uint64_t virtBase, physBase, memSize, topOfKernelData;
	struct boot_video Video;
	uint32_t machineType;
	uint64_t deviceTreeP;
	uint32_t deviceTreeLength;
	char CommandLine[BOOT_LINE_LENGTH];
	uint64_t bootFlags, memSizeActual;
};

_Static_assert(__builtin_offsetof(struct payload, segs) == 0x2a8, "payload header layout");
_Static_assert(__builtin_offsetof(struct boot_args, Video) == 40, "boot_args layout");
_Static_assert(__builtin_offsetof(struct boot_args, CommandLine) == 108, "boot_args layout");
_Static_assert(sizeof(struct boot_args) == 736, "boot_args layout");

/* MMU off: everything is Device memory, so copy in aligned 8-byte words. */
static void copy64(uintptr_t dst, uintptr_t src, uint64_t n)
{
	volatile uint64_t *d = (volatile uint64_t *)dst;
	volatile const uint64_t *s = (volatile const uint64_t *)src;
	for (uint64_t i = 0; i < (n + 7) / 8; i++)
		d[i] = s[i];
}

static void zero64(uintptr_t dst, uint64_t n)
{
	volatile uint64_t *d = (volatile uint64_t *)dst;
	for (uint64_t i = 0; i < n / 8; i++)
		d[i] = 0;
}

/* No GPU initialization here. The top-of-bank reservation is outside every accepted XNU window.
 * Publishing magic last makes a missing/partial firmware set fail closed. */
static void stage_gpu_firmware(void)
{
 extern const uint8_t _gpu_fw_start[], _gpu_fw_end[];
 extern const uint8_t _sqe_fw_start[], _sqe_fw_end[];
 extern const uint8_t _zap_fw_start[], _zap_fw_end[];
 volatile struct fg_handoff *h = (volatile struct fg_handoff *)FG_HANDOFF;
 zero64(FG_HANDOFF, PAGE_16K);
 h->version = 1; h->bytes = sizeof(*h);
 h->base = FG_SCRATCH; h->size = FG_SCRATCH_SIZE;
 for (unsigned i = 0; i < 3; i++) {
  const uint8_t *start = i == 0 ? _gpu_fw_start : i == 1 ? _sqe_fw_start : _zap_fw_start;
  uintptr_t end = i == 0 ? (uintptr_t)_gpu_fw_end : i == 1 ? (uintptr_t)_sqe_fw_end : (uintptr_t)_zap_fw_end;
  unsigned n = end - (uintptr_t)start;
  if (!n || n > FG_FW_SLOT) return;
  /* Firmware is 4-byte aligned, not necessarily 8-byte padded. */
  volatile uint32_t *dst = (volatile uint32_t *)(FG_FW_BASE + i * FG_FW_SLOT);
  for (unsigned off = 0; off < n / 4; off++) dst[off] = ((const uint32_t *)start)[off];
  h->fw_size[i] = n;
  h->fw_hash[i] = fg_hash((const uint8_t *)dst, n);
 }
 __asm__ volatile("dsb sy" ::: "memory");
 h->magic = FG_MAGIC;
}

static int magic_ok(const char *m)
{
	static const char want[] = "SWEETXNU";
	for (int i = 0; i < 8; i++)
		if (m[i] != want[i])
			return 0;
	return 1;
}

typedef void (*xnu_entry_t)(uint64_t boot_args_pa);

static const char *loader_boot(void)
{

 extern const unsigned char _payload_start[], _payload_end[];
 uint64_t rd_start = (uintptr_t)_payload_start, rd_end = (uintptr_t)_payload_end;
 uint64_t length = rd_end - rd_start;
 const struct payload *p = (const struct payload *)rd_start;
 if (length < sizeof(*p) || !magic_ok(p->magic) || p->version != 1 ||
     p->nsegs == 0 || p->nsegs > 32 ||
     length < sizeof(*p) + p->nsegs * sizeof(struct payload_seg))
  return "bad embedded payload header";
 if (p->phys_base != 0x8c0000000ULL || (p->mem_size != 0x40000000ULL && p->mem_size != FG_RAM_SIZE) ||
     (p->virt_base & (0x2000000-1)) || (p->kernel_end & (PAGE_16K-1)) ||
     p->kernel_end < p->virt_base ||
     p->kernel_end - p->virt_base > p->mem_size - 2*PAGE_16K ||
     !p->adt_size || p->adt_size > PAGE_16K || (p->adt_off & 7) ||
     p->adt_off > length || p->adt_size > length-p->adt_off ||
     p->cmdline[BOOT_LINE_LENGTH-1])
  return "unsafe Fuxi memory layout";
 int entry_found = 0;
 for (uint32_t i=0; i<p->nsegs; i++) {
  const struct payload_seg *s = &p->segs[i];
  if (s->vmaddr < p->virt_base || s->vmaddr > p->kernel_end ||
      s->vmsize > p->kernel_end-s->vmaddr || s->file_size > s->vmsize ||
      (s->vmaddr & 7) || (s->vmsize & 7) || (s->file_off & 7) ||
      s->file_off > length || s->file_size > length-s->file_off ||
      ((s->file_size+7)&~7ULL) > length-s->file_off)
   return "unsafe payload segment";
  for (uint32_t j=0;j<i;j++) {
   const struct payload_seg *t=&p->segs[j];
   if (s->vmaddr < t->vmaddr+t->vmsize && t->vmaddr < s->vmaddr+s->vmsize)
    return "overlapping segments";
  }
  if (p->entry_va >= s->vmaddr && p->entry_va-s->vmaddr < s->file_size)
   entry_found=1;
 }
 if (!entry_found) return "entry outside kernel segments";

 /* Reject all loader/FDT overlap with the reservation before writing it. */
 { /* All supported layouts exclude the same top-of-bank scratch. */
  if ((rd_start < FG_SCRATCH + FG_SCRATCH_SIZE && FG_SCRATCH < rd_end) ||
      (probe_fdt_address() < FG_SCRATCH + FG_SCRATCH_SIZE &&
       FG_SCRATCH < probe_fdt_address() + probe_fdt_bytes()))
   return "GPU reservation overlaps loader/FDT";
  stage_gpu_firmware();
 }
 monitor_report[MON_STAGE]=5;
	uint64_t pa_of_va_base = p->phys_base - p->virt_base;	/* pa = va + this */
	con_hex2("PHYS", "base=", p->phys_base, "size=", p->mem_size);
	con_hex("VIRT", p->virt_base);
	con_hex("ENTRY", p->entry_va);

	/* The payload must not overlap where the kernel goes. */
	if (rd_end > p->phys_base && rd_start < p->phys_base + p->mem_size)
		return "ramdisk overlaps kernel memory";

	for (uint32_t i = 0; i < p->nsegs; i++) {
		const struct payload_seg *s = &p->segs[i];
		uintptr_t dst = s->vmaddr + pa_of_va_base;
		zero64(dst, s->vmsize);
		copy64(dst, rd_start + s->file_off, s->file_size);
		if (s->vmsize > s->file_size)
			zero64(dst + ((s->file_size + 7) & ~7UL), s->vmsize - ((s->file_size + 7) & ~7UL));
	}
	con_hex2("SEGS", "n=", p->nsegs, "end=", p->kernel_end + pa_of_va_base);

 monitor_report[MON_STAGE]=6;
	/* ADT, then boot_args, behind the kernel; everything below topOfKernelData is ours. */
	uintptr_t adt_pa = p->kernel_end + pa_of_va_base;
	copy64(adt_pa, rd_start + p->adt_off, p->adt_size);
	uintptr_t ba_pa = (adt_pa + p->adt_size + PAGE_16K - 1) & ~(PAGE_16K - 1);
	uintptr_t top = ba_pa + PAGE_16K;

	zero64(ba_pa, PAGE_16K);
	volatile struct boot_args *ba = (volatile struct boot_args *)ba_pa;
	ba->Revision = 2;
	ba->Version = 2;
	ba->virtBase = p->virt_base;
	ba->physBase = p->phys_base;
	ba->memSize = p->mem_size;
	ba->topOfKernelData = top;
	ba->Video.v_baseAddr = FB_BASE;
	ba->Video.v_display = 1;
	ba->Video.v_rowBytes = FB_STRIDE;
	ba->Video.v_width = FB_W;
	ba->Video.v_height = FB_H;
	ba->Video.v_depth = 32;
	ba->deviceTreeP = adt_pa - pa_of_va_base;	/* xnu reads it with the MMU on: a VA */
	ba->deviceTreeLength = (uint32_t)p->adt_size;
	for (int i = 0; i < BOOT_LINE_LENGTH; i++)
		ba->CommandLine[i] = p->cmdline[i];
	ba->memSizeActual = p->mem_size;
	con_hex2("BOOTARG", "pa=", ba_pa, "top=", top);

 monitor_report[MON_BOOT_ARGS]=ba_pa;
 monitor_report[MON_STAGE]=7;
	uintptr_t entry_pa = p->entry_va + pa_of_va_base;
 monitor_report[MON_ENTRY]=entry_pa;
	con_hex("JUMP", entry_pa);
	con_str("XNU", "jumping (fbcon clears screen)");

	/* Everything was written with the MMU and caches off; drop any stale I-cache lines too. */
	__asm__ volatile("dsb sy; ic iallu; dsb sy; isb" ::: "memory");
 monitor_report[MON_STAGE]=8;
 __asm__ volatile("dsb sy" ::: "memory");
	((xnu_entry_t)entry_pa)(ba_pa);
	return "xnu returned";
}


/* ---------------- dual boot: volume-up selects iOS ----------------
 * The kernel's sweet_spmi.c reads PMIC registers through the arbiter's observer
 * channel; the same sequence works here because the loader runs with the
 * firmware's identity map still active.  Volume-up (PM8550 SID 1 GPIO6, RT_STS
 * bit 0, active low) is sampled while a countdown runs: held means "boot iOS",
 * otherwise the loader resets the SoC and ABL continues into Android.
 *
 * Build with -DFUXI_DUAL_BOOT=1 for the menu image; the default image boots
 * straight into iOS so the automated runs are unaffected.
 */
#ifndef FUXI_DUAL_BOOT
#define FUXI_DUAL_BOOT 0
#endif

#define FK_CORE_PA  0x0c400000ull
#define FK_CNFG_PA  0x0c42d000ull
#define FK_OBS_PA   0x0c440000ull
#define FK_MAP_OFF  0x2000u
#define FK_GPIO_PPID 0x18du        /* SID 1 GPIO6 = volume up */
#define FK_GPIO5_PPID 0x18cu       /* SID 1 GPIO5 = volume down */
#define FK_PON_PPID  0x013u

static uint32_t
fk_rd(uintptr_t base, uint32_t off)
{
	uint32_t v = *(volatile uint32_t *)(uintptr_t)(base + off);
	__asm__ volatile("dmb oshld" ::: "memory");
	return v;
}

static int
fk_find_apid(uint16_t ppid)
{
	int found = -1;
	for (uint32_t i = 0; i < 1024; i++) {
		uint32_t map = fk_rd(FK_CORE_PA, FK_MAP_OFF + 4u * i);
		if (!map || ((map >> 8) & 0xfffu) != ppid) {
			continue;
		}
		unsigned owner = fk_rd(FK_CNFG_PA, 4u * i) & 7u;
		if (found < 0 || owner == 0) {
			found = (int)i;
		}
	}
	return found;
}

static int
fk_read8(int apid, uint8_t reg, uint8_t *out)
{
	if (apid < 0) {
		return 0;
	}
	uint32_t off = 0x20u * (uint32_t)apid;
	__asm__ volatile("dmb oshst" ::: "memory");
	*(volatile uint32_t *)(uintptr_t)(FK_OBS_PA + off) = (1u << 27) | ((uint32_t)reg << 4);
	__asm__ volatile("dsb osh" ::: "memory");
	for (unsigned i = 0; i < 1000; i++) {
		uint32_t st = fk_rd(FK_OBS_PA, off + 8u);
		if (st & 1u) {
			if (st & 0x0eu) {
				return 0;
			}
			*out = (uint8_t)fk_rd(FK_OBS_PA, off + 0x18u);
			return 1;
		}
		for (volatile int d = 0; d < 200; d++) {
		}
	}
	return 0;
}

static uint64_t
fuxi_now(void)
{
	uint64_t v;
	__asm__ volatile("mrs %0, cntpct_el0" : "=r"(v));
	return v;
}

static uint64_t
fuxi_freq(void)
{
	uint64_t v;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
}

static int
fuxi_vol_up(int apid)
{
	uint8_t rt = 0;
	if (!fk_read8(apid, 0x10, &rt)) {
		return 0;
	}
	return (rt & 1u) == 0;      /* GPIO6 is active low */
}

static void
fuxi_psci_reset(void)
{
	register uint64_t x0 __asm__("x0") = 0x84000009ull;   /* SYSTEM_RESET */
	__asm__ volatile("smc #0" :: "r"(x0) : "x1", "x2", "x3", "memory");
	for (;;) {
		__asm__ volatile("wfe");
	}
}

static void
fuxi_dual_boot(void)
{
#if FUXI_DUAL_BOOT
	int up = fk_find_apid(FK_GPIO_PPID);
	int down = fk_find_apid(FK_GPIO5_PPID);
	uint64_t freq = fuxi_freq();
	unsigned seconds = 15;

	/* Interactive, no key held at power-on: volume-up boots iOS, volume-down
	 * returns to Android, and doing nothing boots iOS. */
	con_str("BOOT MENU", "VOL+ = iOS   VOL- = Android   (15 s, default iOS)");
	while (seconds > 0) {
		con_hex("SECONDS", (uintptr_t)seconds);
		uint64_t until = fuxi_now() + freq;
		while (fuxi_now() < until) {
			if (fuxi_vol_up(up)) {
				con_str("BOOT MENU", "volume-up: starting iOS");
				return;
			}
			if (fuxi_vol_up(down)) {
				con_str("BOOT MENU", "volume-down: resetting into Android");
				fuxi_psci_reset();
			}
			__asm__ volatile("yield");
		}
		seconds--;
	}
	con_str("BOOT MENU", "no key: starting iOS (default)");
#else
	(void)fk_find_apid;
	(void)fk_read8;
	(void)fuxi_vol_up;
	(void)fuxi_psci_reset;
	(void)fuxi_now;
	(void)fuxi_freq;
#endif
}

void loader_main(uintptr_t fdt)
{
 probe_main(fdt);
 monitor_report[MON_STAGE]=4;
 /* Refuse to draw unless ABL left the measured SSPP0/CTL0 splash active. */
 volatile uint32_t *sspp=(volatile uint32_t *)0xae05000;
 if (sspp[0x14/4] != 0xb8000000 || sspp[0x24/4] != 4320 ||
     sspp[0] != ((2400u<<16)|1080u) || sspp[0x30/4] != 0x237ff)
  con_fb=0; /* USB diagnostics also work without a usable inherited scanout. */
 con_clear(BLUE);
 con_str("FUXI", "XNU loader + USB monitor");
 {uint8_t rt=0; int apid=fk_find_apid(FK_GPIO_PPID); int ok=fk_read8(apid,0x10,&rt);
  con_hex("APID",(uintptr_t)apid); con_hex("RT",(uintptr_t)rt); con_hex("OK",(uintptr_t)ok);
  con_str("HOLD", fuxi_vol_up(fk_find_apid(FK_GPIO_PPID)) ? "volume-up = iOS" : "no key -> Android");}
 fuxi_dual_boot();
 const char *error=loader_boot();
 con_str("ERROR", error);
 for (unsigned i=0;i<sizeof(monitor_error)-1 && error[i];i++) monitor_error[i]=error[i];
 monitor_report[MON_STAGE]=99;
 __asm__ volatile("dsb sy" ::: "memory");
 for (;;) __asm__ volatile("wfe");
}
