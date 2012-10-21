// Copyright (C) 2003, Matt Conover (mconover@gmail.com)
#include "cpu.h"
#include <assert.h>

// NOTE: this assumes default scenarios (i.e., we assume CS/DS/ES/SS and flat
// and all have a base of 0 and limit of 0xffffffff, we don't try to verify
// that in the GDT)
//
// TODO: use inline assembly to get selector for segment
// Segment = x86 segment register (SEG_ES = 0, SEG_CS = 1, ...)
BYTE *GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset)
{
	switch (Segment)
	{
		// Windows uses a flat address space (except FS for x86 and GS for x64)
		case 0: // SEG_ES
		case 1: // SEG_CS
		case 2: // SEG_SS
		case 3: // SEG_DS
			return (BYTE *)(DWORD_PTR)Offset;
		case 4: // SEG_FS
		case 5: // SEG_GS
			return (BYTE *)(DWORD_PTR)Offset;
			// Note: we're really supposed to do this, but get_teb is not implemented
			// in this bastardized version of the disassembler.
			// return (BYTE *)get_teb() + Offset;
		default:
			assert(0);
			return (BYTE *)(DWORD_PTR)Offset;
	}
}

// This is an GDT/LDT selector (pGDT+Selector)
BYTE *GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset)
{
	DESCRIPTOR_ENTRY Entry;
	GATE_ENTRY *Gate;
	ULONG_PTR Base;
	
	assert(Selector < 0x10000);
	if (!GetThreadSelectorEntry(GetCurrentThread(), Selector, (LDT_ENTRY *)&Entry)) return NULL;
	if (!Entry.Present) return NULL;
	if (Entry.System)
	{
		Base = 0;
#ifdef _WIN64
		Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
		Base |= Entry.BaseHi << 24;
		Base |= Entry.BaseMid << 16;
		Base |= Entry.BaseLow;
	}
	else
	{
		switch (Entry.Type)
		{
			case 1: // 16-bit TSS (available)
			case 2: // LDT
			case 3: // 16-bit TSS (busy)
			case 9: // 32-bit TSS (available)
			case 11: // 32-bit TSS (busy)
				Base = 0;
#ifdef _WIN64
				Base |= (ULONG_PTR)Entry.HighOffset64 << 32;
#endif
				Base |= Entry.BaseHi << 24;
				Base |= Entry.BaseMid << 16;
				Base |= Entry.BaseLow;
				break;

			case 4: // 16-bit call gate
			case 5: // task gate
			case 6: // 16-bit interrupt gate
			case 7: // 16-bit task gate
			case 12: // 32-bit call gate
			case 14: // 32-bit interrupt gate
			case 15: // 32-bit trap gate
				Gate = (GATE_ENTRY *)&Entry;
#ifdef _WIN64
				Base = ((ULONG_PTR)Gate->HighOffset64 << 32) | (Gate->HighOffset << 16) | Gate->LowOffset;
#else
				Base = (Gate->HighOffset << 16) | Gate->LowOffset;
#endif
				assert(!Offset); Offset = 0;
				break;
			default:
				assert(0);
				return NULL;
		}
	}
	return (BYTE *)Base + Offset;
}
