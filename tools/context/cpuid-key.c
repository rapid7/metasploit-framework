/*
 * outputs a cpuid key for use in context keyed payload encoding.
 *
 * Author: Dimitris Glynos <dimitris at census-labs.com>
 */


#include <stdio.h>

int main()
{
	unsigned long eax;

        asm (
		"xorl %%esi, %%esi;" /* esi is key store, zero it out */
		"xorl %%edi, %%edi;" /* edi is loop iterator, ditto */
		"cpuid_loop: movl %%edi, %%eax;" /* iterator is first arg 
                                                    to cpuid */
		"xorl %%ecx, %%ecx;" /* ecx is also used as arg to cpuid but
                                        we'll use it always as zero */
		"cpuid;"
		"xorl %%eax, %%esi;"
		"cmpl %%esi, %%eax;" 	/* first time round esi = eax */
					/* not very safe heh? */
		"jne not_first_time;"
		"leal 0x1(%%eax, 1), %%edi;" /* first time round ... */
		"not_first_time: xorl %%ebx, %%esi;"
		"xorl %%ecx, %%esi;"
		"xorl %%edx, %%esi;"
		"subl $1, %%edi;"
		"jne cpuid_loop;"
		"movl %%esi, %%eax;"
                : "=a" (eax)
        );

	printf("%#.8lx\n", eax);
	return 0;
}
