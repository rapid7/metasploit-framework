// This is a slightly modified copy of the METASM pe-ia32-cpuid.rb example

/*
#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this sample shows the compilation of a slightly more complex program
# it displays in a messagebox the result of CPUID
#

*/

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
	unsigned long i;

	cpuid(0);
	fprintf(stdout, "VENDOR: %.4s%.4s%.4s\n", (char *)&ebx, (char *)&edx, (char *)&ecx);

	cpuid(1);
	fprintf(stdout, "MODEL: family=%ld model=%ld stepping=%ld efamily=%ld emodel=%ld ",
			b(eax, 8, 11), b(eax, 4, 7), b(eax, 0, 3), b(eax, 20, 27), b(eax, 16, 19));
	fprintf(stdout, "brand=%ld cflush sz=%ld*8 nproc=%ld apicid=%ld\n",
			b(ebx, 0, 7), b(ebx, 8, 15), b(ebx, 16, 23), b(ebx, 24, 31));

	fprintf(stdout, "FLAGS:");
	for (i=0 ; i<32 ; i++)
		if (edx & (1 << i))
			fprintf(stdout, " %s", featureinfo[i]);

	for (i=0 ; i<32 ; i++)
		if (ecx & (1 << i))
			fprintf(stdout, " %s", extendinfo[i]);

	fprintf(stdout, "\n");
	fflush(stdout);

	return 0;
}

