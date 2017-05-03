// Copyright (C) 2003, Matt Conover (mconover@gmail.com)
#ifndef CPU_H
#define CPU_H
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(push,1)

#include <windows.h>
#include "misc.h"

////////////////////////////////////////////////////////
// System descriptors
////////////////////////////////////////////////////////

#define GDT_NULL 0
#define GDT_R0_CODE 0x08
#define GDT_R0_DATA 0x10
#define GDT_R3_CODE 0x18
#define GDT_R3_DATA 0x20
#define GDT_TSS 0x28
#define GDT_PCR 0x30
#define GDT_R3_TEB 0x38
#define GDT_VDM 0x40
#define GDT_LDT 0x48
#define GDT_DOUBLEFAULT_TSS 0x50
#define GDT_NMI_TSS 0x58

// 16-bit GDT entries:
// TODO: #define GDT_ABIOS_UNKNOWN   0x60  (22F30-32F2F)
#define GDT_ABIOS_VIDEO 0x68
#define GDT_ABIOS_GDT   0x70 // descriptor describing ABIOS GDT itself
#define GDT_ABIOS_NTOS  0x78 // first 64K of NTOSKRNL
#define GDT_ABIOS_CDA   0xE8 // common data area
#define GDT_ABIOS_CODE  0xF0 // KiI386AbiosCall
#define GDT_ABIOS_STACK 0xF8

#define SELECTOR_RPL_MASK 0x03 // bits 0-1
#define SELECTOR_LDT      0x04 // bit 2

// for data selectors
#define DATA_ACCESS_MASK       (1<<0)
#define DATA_WRITE_ENABLE_MASK (1<<1)
#define DATA_EXPAND_DOWN_MASK  (1<<2)

// for code selectors
#define CODE_ACCESS_MASK       (1<<0)
#define CODE_READ_MASK         (1<<1)
#define CODE_CONFORMING_MASK   (1<<2)
#define CODE_FLAG              (1<<3)

#define TASK_GATE      5
#define INTERRUPT_GATE 6
#define TRAP_GATE      7

typedef struct _IDT_ENTRY
{
   USHORT LowOffset;
   USHORT Selector;
   UCHAR Ignored : 5;
   UCHAR Zero : 3;
   UCHAR Type : 3;
   UCHAR Is32Bit : 1;
   UCHAR Ignored2 : 1;
   UCHAR DPL : 2;
   UCHAR Present : 1;
   USHORT HighOffset;
#ifdef _WIN64
   ULONG HighOffset64;
   ULONG Reserved;
#endif
} IDT_ENTRY, TRAP_GATE_ENTRY;

typedef struct _CALL_GATE_ENTRY
{
   USHORT LowOffset;
   USHORT Selector;
   UCHAR ParameterCount: 4;
   UCHAR Ignored : 3;
   UCHAR Type : 5;
   UCHAR DPL : 2;
   UCHAR Present : 1;
   USHORT HighOffset;
#ifdef _WIN64
   ULONG HighOffset64;
   ULONG Reserved;
#endif
} CALL_GATE_ENTRY;

typedef struct _TASK_GATE_ENTRY
{
   USHORT Ignored;
   USHORT Selector;
   UCHAR Ignored2 : 5;
   UCHAR Zero : 3;
   UCHAR Type : 5;
   UCHAR DPL : 2;
   UCHAR Present : 1;
   USHORT Ignored3;
} TASK_GATE_ENTRY;

typedef struct _DESCRIPTOR_ENTRY
{
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMid;
    UCHAR   Type : 4;        // 10EWA (code), E=ExpandDown, W=Writable, A=Accessed
                             // 11CRA (data), C=Conforming, R=Readable, A=Accessed
    UCHAR   System : 1;      // if 1 then it is a gate or LDT
    UCHAR   DPL : 2;         // descriptor privilege level; 
                             // for data selectors, MAX(CPL, RPL) must be <= DPL to access (or else GP# fault)
                             // for non-conforming code selectors (without callgate), MAX(CPL, RPL) must be <= DPL to access (or else GP# fault)
                             // for conforming code selectors, MAX(CPL, RPL) must be >= DPL (i.e., CPL 0-2 cannot access if DPL is 3)
                             // for non-conforming code selectors (with call gate), DPL indicates lowest privilege allowed to access gate
    UCHAR   Present : 1;
    UCHAR   LimitHigh : 4;
    UCHAR   Available: 1;    // aka AVL
    UCHAR   Reserved : 1;
    UCHAR   Is32Bit : 1;     // aka B flag
    UCHAR   Granularity : 1; // aka G flag
    UCHAR   BaseHi : 8;
#ifdef _WIN64
   ULONG HighOffset64;
   ULONG Reserved2;
#endif
} DESCRIPTOR_ENTRY;

typedef struct _GATE_ENTRY
{
   USHORT LowOffset;
   UCHAR Skip;
   UCHAR Type : 5;
   UCHAR DPL : 2;
   UCHAR Present : 1;
   USHORT HighOffset;
#ifdef _WIN64
   ULONG HighOffset64;
   ULONG Reserved;
#endif
} GATE_ENTRY;

// TODO: update for X64
typedef struct _PTE_ENTRY
{
    ULONG Present : 1;
    ULONG Write : 1;
    ULONG Owner : 1; // E.g., user mode or supervisor mode
    ULONG WriteThrough : 1;
    ULONG CacheDisable : 1;
    ULONG Accessed : 1;
    ULONG Dirty : 1;
    ULONG PAT : 1;
    ULONG Global : 1;
    ULONG CopyOnWrite : 1;
    ULONG Prototype : 1;
    ULONG Transition : 1;
    ULONG Address : 20;
} PTE_ENTRY;

// TODO: update for X64
typedef struct _PDE_ENTRY
{
	ULONG Present : 1;
	ULONG Write : 1;
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Reserved1 : 1;
	ULONG PageSize : 1;
	ULONG Global : 1;
	ULONG Reserved : 3;
	ULONG Address : 20;
} PDE_ENTRY;

// TODO: update for X64
typedef struct _IO_ACCESS_MAP
{
    UCHAR DirectionMap[32];
    UCHAR IoMap[8196];
} IO_ACCESS_MAP;

#define MIN_TSS_SIZE FIELD_OFFSET(TSS_ENTRY, IoMaps)
// TODO: update for X64
typedef struct _TSS_ENTRY
{
    USHORT  Backlink;
    USHORT  Reserved0;
    ULONG   Esp0;
    USHORT  Ss0;
    USHORT  Reserved1;
    ULONG   NotUsed1[4];
    ULONG   CR3;
    ULONG   Eip;
    ULONG   NotUsed2[9];
    USHORT  Es;
    USHORT  Reserved2;
    USHORT  Cs;
    USHORT  Reserved3;
    USHORT  Ss;
    USHORT  Reserved4;
    USHORT  Ds;
    USHORT  Reserved5;
    USHORT  Fs;
    USHORT  Reserved6;
    USHORT  Gs;
    USHORT  Reserved7;
    USHORT  LDT;
    USHORT  Reserved8;
    USHORT  Flags;
    USHORT  IoMapBase;
    IO_ACCESS_MAP IoMaps[1];
    UCHAR IntDirectionMap[32];
} TSS_ENTRY;

// TODO: update for X64
typedef struct _TSS16_ENTRY
{
    USHORT  Backlink;
    USHORT  Sp0;
    USHORT  Ss0;
    USHORT  Sp1;
    USHORT  Ss1;
    USHORT  Sp2;
    USHORT  Ss3;
    USHORT  Ip;
    USHORT  Flags;
    USHORT  Ax;
    USHORT  Cx;
    USHORT  Dx;
    USHORT  Bx;
    USHORT  Sp;
    USHORT  Bp;
    USHORT  Si;
    USHORT  Di;
    USHORT  Es;
    USHORT  Cs;
    USHORT  Ss;
    USHORT  Ds;
    USHORT  LDT;
} TSS16_ENTRY;

// TODO: update for X64
typedef struct _GDT_ENTRY
{
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMid;
            UCHAR   Flags1;
            UCHAR   Flags2;
            UCHAR   BaseHi;
        } Bytes;
        struct {
            ULONG   BaseMid : 8;
            ULONG   Type : 5;
            ULONG   Dpl : 2;
            ULONG   Pres : 1;
            ULONG   LimitHi : 4;
            ULONG   Sys : 1;
            ULONG   Reserved_0 : 1;
            ULONG   Default_Big : 1;
            ULONG   Granularity : 1;
            ULONG   BaseHi : 8;
        } Bits;
    } HighWord;
} GDT_ENTRY;

BYTE *GetAbsoluteAddressFromSegment(BYTE Segment, DWORD Offset);
BYTE *GetAbsoluteAddressFromSelector(WORD Selector, DWORD Offset);

#pragma pack(pop)
#ifdef __cplusplus
}
#endif
#endif // CPU_H