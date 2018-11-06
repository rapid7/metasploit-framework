#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this sample shows the compilation of a slightly more complex program
# it displays in a messagebox the result of CPUID
#

require 'metasm'

pe = Metasm::PE.assemble Metasm::Ia32.new, <<EOS
.text
m_cpuid macro nr
	xor ebx, ebx
	and ecx, ebx
	and edx, ebx
	mov eax, nr
	cpuid
endm

.entrypoint

push ebx push ecx push edx

m_cpuid(0)
mov [cpuname], ebx
mov [cpuname+4], edx
mov [cpuname+8], ecx
and byte ptr [cpuname+12], 0

m_cpuid(0x8000_0000)
and eax, 0x8000_0000
jz extended_unsupported

m_str_cpuid macro nr
	m_cpuid(0x8000_0002 + nr)
	mov [cpubrand + 16*nr + 0], eax
	mov [cpubrand + 16*nr + 4], ebx
	mov [cpubrand + 16*nr + 8], ecx
	mov [cpubrand + 16*nr + 12], edx
endm

m_str_cpuid(0)
m_str_cpuid(1)
m_str_cpuid(2)

extended_unsupported:
and byte ptr[cpubrand+48], 0

push cpubrand
push cpuname
push format
push buffer
call wsprintf
add esp, 4*4

push 0
push title
push buffer
push 0
call messagebox

pop edx pop ecx pop ebx

xor eax, eax
ret

.import user32 MessageBoxA messagebox
.import user32 wsprintfA wsprintf

#define PE_HOOK_TARGET
#ifdef PE_HOOK_TARGET
; import these to be a good target for pe-hook.rb
.import kernel32 LoadLibraryA
.import kernel32 GetProcAddress
#endif

.data
format  db 'CPU: %s\\nBrandstring: %s', 0
title   db 'cpuid', 0

.bss
buffer  db 1025 dup(?)
.align 4
cpuname db 3*4+1 dup(?)
.align 4
cpubrand db 3*4*4+1 dup(?)

EOS

pe.encode_file('metasm-cpuid.exe')

__END__

// original C code (more complete)

#include <unistd.h>
#include <stdio.h>

static char *featureinfo[32] = {
	"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8",
	"apic", "unk10", "sep", "mtrr", "pge", "mca", "cmov", "pat",
	"pse36", "psn", "clfsh", "unk20", "ds", "acpi", "mmx",
	"fxsr", "sse", "sse2", "ss", "htt", "tm", "unk30", "pbe"
}, *extendinfo[32] = {
	"sse3", "unk1", "unk2", "monitor", "ds-cpl", "unk5-vt", "unk6", "est",
	"tm2", "unk9", "cnxt-id", "unk12", "cmpxchg16b", "unk14", "unk15",
	"unk16", "unk17", "unk18", "unk19", "unk20", "unk21", "unk22", "unk23",
	"unk24", "unk25", "unk26", "unk27", "unk28", "unk29", "unk30", "unk31"
};

#define cpuid(id) __asm__( "cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(id), "b"(0), "c"(0), "d"(0))
#define b(val, base, end) ((val << (31-end)) >> (31-end+base))
int main(void)
{
	unsigned long eax, ebx, ecx, edx;
	unsigned long i, max;
	int support_extended;

	printf("%8s - %8s %8s %8s %8s\n", "query", "eax", "ebx", "ecx", "edx");

	max = 0;
	for (i=0 ; i<=max ; i++) {
		cpuid(i);
		if (!i)
			max = eax;
		printf("%.8lX - %.8lX %.8lX %.8lX %.8lX\n", i, eax, ebx, ecx, edx);
	}
	printf("\n");

	max = 0x80000000;
	for (i=0x80000000 ; i<=max ; i++) {
		cpuid(i);
		if (!(i << 1)) {
			max = eax;
			support_extended = eax >> 31;
		}
		printf("%.8lX - %.8lX %.8lX %.8lX %.8lX\n", i, eax, ebx, ecx, edx);
	}
	printf("\n");

	cpuid(0);
	printf("identification: \"%.4s%.4s%.4s\"\n", (char *)&ebx, (char *)&edx, (char *)&ecx);

	printf("cpu information:\n");
	cpuid(1);
	printf(" family %ld model %ld stepping %ld efamily %ld emodel %ld\n",
			b(eax, 8, 11), b(eax, 4, 7), b(eax, 0, 3), b(eax, 20, 27), b(eax, 16, 19));
	printf(" brand %ld cflush sz %ld*8 nproc %ld apicid %ld\n",
			b(ebx, 0, 7), b(ebx, 8, 15), b(ebx, 16, 23), b(ebx, 24, 31));

	printf(" feature information:");
	for (i=0 ; i<32 ; i++)
		if (edx & (1 << i))
			printf(" %s", featureinfo[i]);

	printf("\n extended information:");
	for (i=0 ; i<32 ; i++)
		if (ecx & (1 << i))
			printf(" %s", extendinfo[i]);
	printf("\n");

	if (!support_extended)
		return 0;

	printf("extended cpuid:\n", eax);
	cpuid(0x80000001);
	printf(" %.8lX %.8lX %.8lX %.8lX + ", eax, ebx, ecx & ~1, edx & ~0x00800102);
	if (ecx & 1)
		printf(" lahf64");

	if (edx & (1 << 11))
		printf(" syscall64");
	if (edx & (1 << 20))
		printf(" nx");
	if (edx & (1 << 29))
		printf(" em64t");

	char brandstring[48];
	unsigned long *p = (unsigned long*)brandstring;
	cpuid(0x80000002);
	*p++ = eax;
	*p++ = ebx;
	*p++ = ecx;
	*p++ = edx;
	cpuid(0x80000003);
	*p++ = eax;
	*p++ = ebx;
	*p++ = ecx;
	*p++ = edx;
	cpuid(0x80000004);
	*p++ = eax;
	*p++ = ebx;
	*p++ = ecx;
	*p++ = edx;
	printf("\n brandstring: \"%.48s\"\n", brandstring);

	return 0;
}
