//////////////////////////////////////////////////////////////////////////////
//
//  Detours Disassembler (disasm.cpp of detours.lib)
//
//  Microsoft Research Detours Package, Version 2.1.
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#include <windows.h>
#include <limits.h>

// #define DETOUR_DEBUG 1
#define DETOURS_INTERNAL

#include "detours.h"

#if !defined(DETOURS_X86) && !defined(DETOURS_X64) && !defined(DETOURS_IA64)
#error Must define one of DETOURS_X86, DETOURS_X64, or DETOURS_IA64
#endif

#undef ASSERT
#define ASSERT(x)

//////////////////////////////////////////////////////////////////////////////
//
//  Function:
//      DetourCopyInstructionEx(PVOID pDst,
//                              PVOID pSrc,
//                              PVOID *ppTarget,
//                              LONG *plExtra)
//  Purpose:
//      Copy a single instruction from pSrc to pDst.
//
//  Arguments:
//      pDst:
//          Destination address for the instruction.  May be NULL in which
//          case DetourCopyInstruction is used to measure an instruction.
//          If not NULL then the source instruction is copied to the
//          destination instruction and any relative arguments are adjusted.
//      pSrc:
//          Source address of the instruction.
//      ppTarget:
//          Out parameter for any target instruction address pointed to by
//          the instruction.  For example, a branch or a jump insruction has
//          a target, but a load or store instruction doesn't.  A target is
//          another instruction that may be executed as a result of this
//          instruction.  ppTarget may be NULL.
//      plExtra:
//          Out parameter for the number of extra bytes needed by the
//          instruction to reach the target.  For example, lExtra = 3 if the
//          instruction had an 8-bit relative offset, but needs a 32-bit
//          relative offset.
//
//  Returns:
//      Returns the address of the next instruction (following in the source)
//      instruction.  By subtracting pSrc from the return value, the caller
//      can determinte the size of the instruction copied.
//
//  Comments:
//      By following the pTarget, the caller can follow alternate
//      instruction streams.  However, it is not always possible to determine
//      the target based on static analysis.  For example, the destination of
//      a jump relative to a register cannot be determined from just the
//      instruction stream.  The output value, pTarget, can have any of the
//      following outputs:
//          DETOUR_INSTRUCTION_TARGET_NONE:
//              The instruction has no targets.
//          DETOUR_INSTRUCTION_TARGET_DYNAMIC:
//              The instruction has a non-deterministic (dynamic) target.
//              (i.e. the jump is to an address held in a register.)
//          Address:   The instruction has the specified target.
//
//      When copying instructions, DetourCopyInstruction insures that any
//      targets remain constant.  It does so by adjusting any IP relative
//      offsets.
//

PVOID WINAPI DetourCopyInstruction(PVOID pDst, PVOID pSrc, PVOID *ppTarget)
{
    return DetourCopyInstructionEx(pDst, pSrc, ppTarget, NULL);
}

//////////////////////////////////////////////////// X86 and X64 Disassembler.
//
//  Includes full support for all x86 chips prior to the Pentium III.
//
#if defined(DETOURS_X64) || defined(DETOURS_X86)

class CDetourDis
{
  public:
    CDetourDis(PBYTE *ppbTarget, LONG *plExtra);

    PBYTE   CopyInstruction(PBYTE pbDst, PBYTE pbSrc);
    static BOOL SanityCheckSystem();

  public:
    struct COPYENTRY;
    typedef const COPYENTRY * REFCOPYENTRY;

    typedef PBYTE (CDetourDis::* COPYFUNC)(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    enum {
        DYNAMIC     = 0x1u,
        ADDRESS     = 0x2u,
        NOENLARGE   = 0x4u,
        RAX         = 0x8u,

        SIB         = 0x10u,
        RIP         = 0x20u,
        NOTSIB      = 0x0fu,
    };
    struct COPYENTRY
    {
        ULONG       nOpcode         : 8;    // Opcode
        ULONG       nFixedSize      : 4;    // Fixed size of opcode
        ULONG       nFixedSize16    : 4;    // Fixed size when 16 bit operand
        ULONG       nModOffset      : 4;    // Offset to mod/rm byte (0=none)
        LONG        nRelOffset      : 4;    // Offset to relative target.
        LONG        nTargetBack     : 4;    // Offset back to absolute or rip target
        ULONG       nFlagBits       : 4;    // Flags for DYNAMIC, etc.
        COPYFUNC    pfCopy;                 // Function pointer.
    };

  protected:
    // These macros define common uses of nFixedSize..pfCopy.
#define ENTRY_CopyBytes1            1, 1, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes1Dynamic     1, 1, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2            2, 2, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Jump        2, 2, 0, 1, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2CantJump    2, 2, 0, 1, 0, NOENLARGE, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Dynamic     2, 2, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3            3, 3, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Dynamic     3, 3, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5         5, 3, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Rax      5, 3, 0, 0, 0, RAX, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Target   5, 3, 0, 1, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes5Or7Dynamic  7, 5, 0, 0, 0, DYNAMIC, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Or5Address  5, 3, 0, 0, 0, ADDRESS, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes4            4, 4, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes5            5, 5, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes7            7, 7, 0, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Mod         2, 2, 1, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2Mod1        3, 3, 1, 0, 1, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes2ModOperand  6, 4, 1, 0, 4, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytes3Mod         3, 3, 2, 0, 0, 0, &CDetourDis::CopyBytes
#define ENTRY_CopyBytesPrefix       1, 1, 0, 0, 0, 0, &CDetourDis::CopyBytesPrefix
#define ENTRY_CopyBytesRax          1, 1, 0, 0, 0, 0, &CDetourDis::CopyBytesRax
#define ENTRY_Copy0F                1, 1, 0, 0, 0, 0, &CDetourDis::Copy0F
#define ENTRY_Copy66                1, 1, 0, 0, 0, 0, &CDetourDis::Copy66
#define ENTRY_Copy67                1, 1, 0, 0, 0, 0, &CDetourDis::Copy67
#define ENTRY_CopyF6                0, 0, 0, 0, 0, 0, &CDetourDis::CopyF6
#define ENTRY_CopyF7                0, 0, 0, 0, 0, 0, &CDetourDis::CopyF7
#define ENTRY_CopyFF                0, 0, 0, 0, 0, 0, &CDetourDis::CopyFF
#define ENTRY_Invalid               1, 1, 0, 0, 0, 0, &CDetourDis::Invalid
#define ENTRY_End                   0, 0, 0, 0, 0, 0, NULL

    PBYTE CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesRax(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    PBYTE Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    PBYTE AdjustTarget(PBYTE pbDst, PBYTE pbSrc, LONG cbOp,
                       LONG cbTargetOffset, LONG cbTargetSize);

  protected:
    PBYTE Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

  protected:
    static const COPYENTRY  s_rceCopyTable[257];
    static const COPYENTRY  s_rceCopyTable0F[257];
    static const BYTE       s_rbModRm[256];

  protected:
    BOOL                m_bOperandOverride;
    BOOL                m_bAddressOverride;
    BOOL                m_bRaxOverride;

    PBYTE *             m_ppbTarget;
    LONG *              m_plExtra;

    LONG                m_lScratchExtra;
    PBYTE               m_pbScratchTarget;
    BYTE                m_rbScratchDst[64];
};

PVOID WINAPI DetourCopyInstructionEx(PVOID pDst,
                                     PVOID pSrc,
                                     PVOID *ppTarget,
                                     LONG *plExtra)
{
    CDetourDis oDetourDisasm((PBYTE*)ppTarget, plExtra);
    return oDetourDisasm.CopyInstruction((PBYTE)pDst, (PBYTE)pSrc);
}

/////////////////////////////////////////////////////////// Disassembler Code.
//
CDetourDis::CDetourDis(PBYTE *ppbTarget, LONG *plExtra)
{
    m_bOperandOverride = FALSE;
    m_bAddressOverride = FALSE;
    m_bRaxOverride = FALSE;

    m_ppbTarget = ppbTarget ? ppbTarget : &m_pbScratchTarget;
    m_plExtra = plExtra ? plExtra : &m_lScratchExtra;

    *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_NONE;
    *m_plExtra = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pbDst, PBYTE pbSrc)
{
    // Configure scratch areas if real areas are not available.
    if (NULL == pbDst) {
        pbDst = m_rbScratchDst;
    }
    if (NULL == pbSrc) {
        // We can't copy a non-existent instruction.
        SetLastError(ERROR_INVALID_DATA);
        return NULL;
    }

    // Figure out how big the instruction is, do the appropriate copy,
    // and figure out what the target of the instruction is if any.
    //
    REFCOPYENTRY pEntry = &s_rceCopyTable[pbSrc[0]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
#ifdef DETOURS_X64
#error Feature not supported in this release.




#else
    LONG nBytesFixed = (pEntry->nFlagBits & ADDRESS)
        ? (m_bAddressOverride ? pEntry->nFixedSize16 : pEntry->nFixedSize)
        : (m_bOperandOverride ? pEntry->nFixedSize16 : pEntry->nFixedSize);
#endif

    LONG nBytes = nBytesFixed;
    LONG nRelOffset = pEntry->nRelOffset;
    LONG cbTarget = nBytes - nRelOffset;
    if (pEntry->nModOffset > 0) {
        BYTE bModRm = pbSrc[pEntry->nModOffset];
        BYTE bFlags = s_rbModRm[bModRm];

        nBytes += bFlags & NOTSIB;

        if (bFlags & SIB) {
            BYTE bSib = pbSrc[pEntry->nModOffset + 1];

            if ((bSib & 0x07) == 0x05) {
                if ((bModRm & 0xc0) == 0x00) {
                    nBytes += 4;
                }
                else if ((bModRm & 0xc0) == 0x40) {
                    nBytes += 1;
                }
                else if ((bModRm & 0xc0) == 0x80) {
                    nBytes += 4;
                }
            }
            cbTarget = nBytes - nRelOffset;
        }
        else if (bFlags & RIP) {
#ifdef DETOURS_X64
#error Feature not supported in this release.


#endif
        }
    }
    CopyMemory(pbDst, pbSrc, nBytes);

    if (nRelOffset) {
        *m_ppbTarget = AdjustTarget(pbDst, pbSrc, nBytesFixed, nRelOffset, cbTarget);
#ifdef DETOURS_X64
#error Feature not supported in this release.



#endif
    }
    if (pEntry->nFlagBits & NOENLARGE) {
        *m_plExtra = -*m_plExtra;
    }
    if (pEntry->nFlagBits & DYNAMIC) {
        *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
    return pbSrc + nBytes;
}

PBYTE CDetourDis::CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    CopyBytes(pEntry, pbDst, pbSrc);

    pEntry = &s_rceCopyTable[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::CopyBytesRax(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    CopyBytes(pEntry, pbDst, pbSrc);

    if (*pbSrc & 0x8) {
        m_bRaxOverride = TRUE;
    }

    pEntry = &s_rceCopyTable[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::AdjustTarget(PBYTE pbDst, PBYTE pbSrc, LONG cbOp,
                               LONG cbTargetOffset, LONG cbTargetSize)
{
    PBYTE pbTarget = NULL;
    PVOID pvTargetAddr = &pbDst[cbTargetOffset];
    LONG_PTR nOldOffset = 0;

    switch (cbTargetSize) {
      case 1:
        nOldOffset = (LONG_PTR)*(CHAR*&)pvTargetAddr;
        break;
      case 2:
        nOldOffset = (LONG_PTR)*(SHORT*&)pvTargetAddr;
        break;
      case 4:
        nOldOffset = (LONG_PTR)*(LONG*&)pvTargetAddr;
        break;
      case 8:
        nOldOffset = (LONG_PTR)*(LONG_PTR*&)pvTargetAddr;
        break;
      default:
        ASSERT(!"cbTargetSize is invalid.");
        break;
    }

    pbTarget = pbSrc + cbOp + nOldOffset;
    LONG_PTR nNewOffset = nOldOffset - (pbDst - pbSrc);

    switch (cbTargetSize) {
      case 1:
        *(CHAR*&)pvTargetAddr = (CHAR)nNewOffset;
        if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX) {
            *m_plExtra = sizeof(ULONG_PTR) - 1;
        }
        break;
      case 2:
        *(SHORT*&)pvTargetAddr = (SHORT)nNewOffset;
        if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
            *m_plExtra = sizeof(ULONG_PTR) - 2;
        }
        break;
      case 4:
        *(LONG*&)pvTargetAddr = (LONG)nNewOffset;
        if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
            *m_plExtra = sizeof(ULONG_PTR) - 4;
        }
        break;
      case 8:
        *(LONG_PTR*&)pvTargetAddr = (LONG_PTR)nNewOffset;
        break;
    }
    ASSERT(pbDst + cbOp + nNewOffset == pbTarget);
    return pbTarget;
}

PBYTE CDetourDis::Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pbDst;
    (void)pEntry;
    ASSERT(!"Invalid Instruction");
    return pbSrc + 1;
}

////////////////////////////////////////////////////// Individual Bytes Codes.
//
PBYTE CDetourDis::Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    CopyBytes(pEntry, pbDst, pbSrc);

    pEntry = &s_rceCopyTable0F[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   // Operand-size override prefix
    m_bOperandOverride = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   // Address size override prefix
    m_bAddressOverride = TRUE;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    // TEST BYTE /0
    if (0x00 == (0x38 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 0
        const COPYENTRY ce = { 0xf6, ENTRY_CopyBytes2Mod1 };
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }
    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2

    const COPYENTRY ce = { 0xf6, ENTRY_CopyBytes2Mod };
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    // TEST WORD /0
    if (0x00 == (0x38 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 0
        const COPYENTRY ce = { 0xf7, ENTRY_CopyBytes2ModOperand };
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }

    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2
    const COPYENTRY ce = { 0xf7, ENTRY_CopyBytes2Mod };
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyFF(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   // CALL /2
    // CALL /3
    // INC /0
    // JMP /4
    // JMP /5
    // PUSH /6
    (void)pEntry;

    if (0x15 == pbSrc[1] || 0x25 == pbSrc[1]) {         // CALL [], JMP []
#ifdef DETOURS_X64
#error Feature not supported in this release.


#else
        PBYTE *ppbTarget = *(PBYTE**)&pbSrc[2];
        *m_ppbTarget = *ppbTarget;
#endif
    }
    else if (0x10 == (0x38 & pbSrc[1]) || // CALL /2 --> reg(bits 543) of ModR/M == 010
             0x18 == (0x38 & pbSrc[1]) || // CALL /3 --> reg(bits 543) of ModR/M == 011
             0x20 == (0x38 & pbSrc[1]) || // JMP /4 --> reg(bits 543) of ModR/M == 100
             0x28 == (0x38 & pbSrc[1])    // JMP /5 --> reg(bits 543) of ModR/M == 101
            ) {
        *m_ppbTarget = (PBYTE)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
    }
    const COPYENTRY ce = { 0xff, ENTRY_CopyBytes2Mod };
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

///////////////////////////////////////////////////////// Disassembler Tables.
//
const BYTE CDetourDis::s_rbModRm[256] = {
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 0x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 1x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 2x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 3x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 4x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 5x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 6x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 7x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 8x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 9x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Ax
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Bx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Cx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Dx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Ex
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  // Fx
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[257] =
{
    { 0x00, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x01, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x02, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x03, ENTRY_CopyBytes2Mod },                      // ADD /r
    { 0x04, ENTRY_CopyBytes2 },                         // ADD ib
    { 0x05, ENTRY_CopyBytes3Or5 },                      // ADD iw
    { 0x06, ENTRY_CopyBytes1 },                         // PUSH
    { 0x07, ENTRY_CopyBytes1 },                         // POP
    { 0x08, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x09, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0A, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0B, ENTRY_CopyBytes2Mod },                      // OR /r
    { 0x0C, ENTRY_CopyBytes2 },                         // OR ib
    { 0x0D, ENTRY_CopyBytes3Or5 },                      // OR iw
    { 0x0E, ENTRY_CopyBytes1 },                         // PUSH
    { 0x0F, ENTRY_Copy0F },                             // Extension Ops
    { 0x10, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x11, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x12, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x13, ENTRY_CopyBytes2Mod },                      // ADC /r
    { 0x14, ENTRY_CopyBytes2 },                         // ADC ib
    { 0x15, ENTRY_CopyBytes3Or5 },                      // ADC id
    { 0x16, ENTRY_CopyBytes1 },                         // PUSH
    { 0x17, ENTRY_CopyBytes1 },                         // POP
    { 0x18, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x19, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1A, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1B, ENTRY_CopyBytes2Mod },                      // SBB /r
    { 0x1C, ENTRY_CopyBytes2 },                         // SBB ib
    { 0x1D, ENTRY_CopyBytes3Or5 },                      // SBB id
    { 0x1E, ENTRY_CopyBytes1 },                         // PUSH
    { 0x1F, ENTRY_CopyBytes1 },                         // POP
    { 0x20, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x21, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x22, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x23, ENTRY_CopyBytes2Mod },                      // AND /r
    { 0x24, ENTRY_CopyBytes2 },                         // AND ib
    { 0x25, ENTRY_CopyBytes3Or5 },                      // AND id
    { 0x26, ENTRY_CopyBytesPrefix },                    // ES prefix
    { 0x27, ENTRY_CopyBytes1 },                         // DAA
    { 0x28, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x29, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2A, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2B, ENTRY_CopyBytes2Mod },                      // SUB /r
    { 0x2C, ENTRY_CopyBytes2 },                         // SUB ib
    { 0x2D, ENTRY_CopyBytes3Or5 },                      // SUB id
    { 0x2E, ENTRY_CopyBytesPrefix },                    // CS prefix
    { 0x2F, ENTRY_CopyBytes1 },                         // DAS
    { 0x30, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x31, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x32, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x33, ENTRY_CopyBytes2Mod },                      // XOR /r
    { 0x34, ENTRY_CopyBytes2 },                         // XOR ib
    { 0x35, ENTRY_CopyBytes3Or5 },                      // XOR id
    { 0x36, ENTRY_CopyBytesPrefix },                    // SS prefix
    { 0x37, ENTRY_CopyBytes1 },                         // AAA
    { 0x38, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x39, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3A, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3B, ENTRY_CopyBytes2Mod },                      // CMP /r
    { 0x3C, ENTRY_CopyBytes2 },                         // CMP ib
    { 0x3D, ENTRY_CopyBytes3Or5 },                      // CMP id
    { 0x3E, ENTRY_CopyBytesPrefix },                    // DS prefix
    { 0x3F, ENTRY_CopyBytes1 },                         // AAS
#ifdef DETOURS_X64 // For Rax Prefix
#error Feature not supported in this release.















#else
    { 0x40, ENTRY_CopyBytes1 },                         // INC
    { 0x41, ENTRY_CopyBytes1 },                         // INC
    { 0x42, ENTRY_CopyBytes1 },                         // INC
    { 0x43, ENTRY_CopyBytes1 },                         // INC
    { 0x44, ENTRY_CopyBytes1 },                         // INC
    { 0x45, ENTRY_CopyBytes1 },                         // INC
    { 0x46, ENTRY_CopyBytes1 },                         // INC
    { 0x47, ENTRY_CopyBytes1 },                         // INC
    { 0x48, ENTRY_CopyBytes1 },                         // DEC
    { 0x49, ENTRY_CopyBytes1 },                         // DEC
    { 0x4A, ENTRY_CopyBytes1 },                         // DEC
    { 0x4B, ENTRY_CopyBytes1 },                         // DEC
    { 0x4C, ENTRY_CopyBytes1 },                         // DEC
    { 0x4D, ENTRY_CopyBytes1 },                         // DEC
    { 0x4E, ENTRY_CopyBytes1 },                         // DEC
    { 0x4F, ENTRY_CopyBytes1 },                         // DEC
#endif
    { 0x50, ENTRY_CopyBytes1 },                         // PUSH
    { 0x51, ENTRY_CopyBytes1 },                         // PUSH
    { 0x52, ENTRY_CopyBytes1 },                         // PUSH
    { 0x53, ENTRY_CopyBytes1 },                         // PUSH
    { 0x54, ENTRY_CopyBytes1 },                         // PUSH
    { 0x55, ENTRY_CopyBytes1 },                         // PUSH
    { 0x56, ENTRY_CopyBytes1 },                         // PUSH
    { 0x57, ENTRY_CopyBytes1 },                         // PUSH
    { 0x58, ENTRY_CopyBytes1 },                         // POP
    { 0x59, ENTRY_CopyBytes1 },                         // POP
    { 0x5A, ENTRY_CopyBytes1 },                         // POP
    { 0x5B, ENTRY_CopyBytes1 },                         // POP
    { 0x5C, ENTRY_CopyBytes1 },                         // POP
    { 0x5D, ENTRY_CopyBytes1 },                         // POP
    { 0x5E, ENTRY_CopyBytes1 },                         // POP
    { 0x5F, ENTRY_CopyBytes1 },                         // POP
    { 0x60, ENTRY_CopyBytes1 },                         // PUSHAD
    { 0x61, ENTRY_CopyBytes1 },                         // POPAD
    { 0x62, ENTRY_CopyBytes2Mod },                      // BOUND /r
    { 0x63, ENTRY_CopyBytes2Mod },                      // ARPL /r
    { 0x64, ENTRY_CopyBytesPrefix },                    // FS prefix
    { 0x65, ENTRY_CopyBytesPrefix },                    // GS prefix
    { 0x66, ENTRY_Copy66 },                             // Operand Prefix
    { 0x67, ENTRY_Copy67 },                             // Address Prefix
    { 0x68, ENTRY_CopyBytes3Or5 },                      // PUSH
    { 0x69, ENTRY_CopyBytes2ModOperand },               //
    { 0x6A, ENTRY_CopyBytes2 },                         // PUSH
    { 0x6B, ENTRY_CopyBytes2Mod1 },                     // IMUL /r ib
    { 0x6C, ENTRY_CopyBytes1 },                         // INS
    { 0x6D, ENTRY_CopyBytes1 },                         // INS
    { 0x6E, ENTRY_CopyBytes1 },                         // OUTS/OUTSB
    { 0x6F, ENTRY_CopyBytes1 },                         // OUTS/OUTSW
    { 0x70, ENTRY_CopyBytes2Jump },                     // JO
    { 0x71, ENTRY_CopyBytes2Jump },                     // JNO
    { 0x72, ENTRY_CopyBytes2Jump },                     // JB/JC/JNAE
    { 0x73, ENTRY_CopyBytes2Jump },                     // JAE/JNB/JNC
    { 0x74, ENTRY_CopyBytes2Jump },                     // JE/JZ
    { 0x75, ENTRY_CopyBytes2Jump },                     // JNE/JNZ
    { 0x76, ENTRY_CopyBytes2Jump },                     // JBE/JNA
    { 0x77, ENTRY_CopyBytes2Jump },                     // JA/JNBE
    { 0x78, ENTRY_CopyBytes2Jump },                     // JS
    { 0x79, ENTRY_CopyBytes2Jump },                     // JNS
    { 0x7A, ENTRY_CopyBytes2Jump },                     // JP/JPE
    { 0x7B, ENTRY_CopyBytes2Jump },                     // JNP/JPO
    { 0x7C, ENTRY_CopyBytes2Jump },                     // JL/JNGE
    { 0x7D, ENTRY_CopyBytes2Jump },                     // JGE/JNL
    { 0x7E, ENTRY_CopyBytes2Jump },                     // JLE/JNG
    { 0x7F, ENTRY_CopyBytes2Jump },                     // JG/JNLE
    { 0x80, ENTRY_CopyBytes2Mod1 },                     // ADC/2 ib, etc.s
    { 0x81, ENTRY_CopyBytes2ModOperand },               //
    { 0x82, ENTRY_CopyBytes2 },                         // MOV al,x
    { 0x83, ENTRY_CopyBytes2Mod1 },                     // ADC/2 ib, etc.
    { 0x84, ENTRY_CopyBytes2Mod },                      // TEST /r
    { 0x85, ENTRY_CopyBytes2Mod },                      // TEST /r
    { 0x86, ENTRY_CopyBytes2Mod },                      // XCHG /r @todo
    { 0x87, ENTRY_CopyBytes2Mod },                      // XCHG /r @todo
    { 0x88, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x89, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8A, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8B, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8C, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8D, ENTRY_CopyBytes2Mod },                      // LEA /r
    { 0x8E, ENTRY_CopyBytes2Mod },                      // MOV /r
    { 0x8F, ENTRY_CopyBytes2Mod },                      // POP /0
    { 0x90, ENTRY_CopyBytes1 },                         // NOP
    { 0x91, ENTRY_CopyBytes1 },                         // XCHG
    { 0x92, ENTRY_CopyBytes1 },                         // XCHG
    { 0x93, ENTRY_CopyBytes1 },                         // XCHG
    { 0x94, ENTRY_CopyBytes1 },                         // XCHG
    { 0x95, ENTRY_CopyBytes1 },                         // XCHG
    { 0x96, ENTRY_CopyBytes1 },                         // XCHG
    { 0x97, ENTRY_CopyBytes1 },                         // XCHG
    { 0x98, ENTRY_CopyBytes1 },                         // CWDE
    { 0x99, ENTRY_CopyBytes1 },                         // CDQ
    { 0x9A, ENTRY_CopyBytes5Or7Dynamic },               // CALL cp
    { 0x9B, ENTRY_CopyBytes1 },                         // WAIT/FWAIT
    { 0x9C, ENTRY_CopyBytes1 },                         // PUSHFD
    { 0x9D, ENTRY_CopyBytes1 },                         // POPFD
    { 0x9E, ENTRY_CopyBytes1 },                         // SAHF
    { 0x9F, ENTRY_CopyBytes1 },                         // LAHF
    { 0xA0, ENTRY_CopyBytes3Or5Address },               // MOV
    { 0xA1, ENTRY_CopyBytes3Or5Address },               // MOV
    { 0xA2, ENTRY_CopyBytes3Or5Address },               // MOV
    { 0xA3, ENTRY_CopyBytes3Or5Address },               // MOV
    { 0xA4, ENTRY_CopyBytes1 },                         // MOVS
    { 0xA5, ENTRY_CopyBytes1 },                         // MOVS/MOVSD
    { 0xA6, ENTRY_CopyBytes1 },                         // CMPS/CMPSB
    { 0xA7, ENTRY_CopyBytes1 },                         // CMPS/CMPSW
    { 0xA8, ENTRY_CopyBytes2 },                         // TEST
    { 0xA9, ENTRY_CopyBytes3Or5 },                      // TEST
    { 0xAA, ENTRY_CopyBytes1 },                         // STOS/STOSB
    { 0xAB, ENTRY_CopyBytes1 },                         // STOS/STOSW
    { 0xAC, ENTRY_CopyBytes1 },                         // LODS/LODSB
    { 0xAD, ENTRY_CopyBytes1 },                         // LODS/LODSW
    { 0xAE, ENTRY_CopyBytes1 },                         // SCAS/SCASB
    { 0xAF, ENTRY_CopyBytes1 },                         // SCAS/SCASD
    { 0xB0, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB1, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB2, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB3, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB4, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB5, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB6, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB7, ENTRY_CopyBytes2 },                         // MOV B0+rb
    { 0xB8, ENTRY_CopyBytes3Or5Rax },                   // MOV B8+rb
    { 0xB9, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBA, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBB, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBC, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBD, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBE, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xBF, ENTRY_CopyBytes3Or5 },                      // MOV B8+rb
    { 0xC0, ENTRY_CopyBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC1, ENTRY_CopyBytes2Mod1 },                     // RCL/2 ib, etc.
    { 0xC2, ENTRY_CopyBytes3 },                         // RET
    { 0xC3, ENTRY_CopyBytes1 },                         // RET
    { 0xC4, ENTRY_CopyBytes2Mod },                      // LES
    { 0xC5, ENTRY_CopyBytes2Mod },                      // LDS
    { 0xC6, ENTRY_CopyBytes2Mod1 },                     // MOV
    { 0xC7, ENTRY_CopyBytes2ModOperand },               // MOV
    { 0xC8, ENTRY_CopyBytes4 },                         // ENTER
    { 0xC9, ENTRY_CopyBytes1 },                         // LEAVE
    { 0xCA, ENTRY_CopyBytes3Dynamic },                  // RET
    { 0xCB, ENTRY_CopyBytes1Dynamic },                  // RET
    { 0xCC, ENTRY_CopyBytes1Dynamic },                  // INT 3
    { 0xCD, ENTRY_CopyBytes2Dynamic },                  // INT ib
    { 0xCE, ENTRY_CopyBytes1Dynamic },                  // INTO
    { 0xCF, ENTRY_CopyBytes1Dynamic },                  // IRET
    { 0xD0, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD1, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD2, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD3, ENTRY_CopyBytes2Mod },                      // RCL/2, etc.
    { 0xD4, ENTRY_CopyBytes2 },                         // AAM
    { 0xD5, ENTRY_CopyBytes2 },                         // AAD
    { 0xD6, ENTRY_Invalid },                            //
    { 0xD7, ENTRY_CopyBytes1 },                         // XLAT/XLATB
    { 0xD8, ENTRY_CopyBytes2Mod },                      // FADD, etc.
    { 0xD9, ENTRY_CopyBytes2Mod },                      // F2XM1, etc.
    { 0xDA, ENTRY_CopyBytes2Mod },                      // FLADD, etc.
    { 0xDB, ENTRY_CopyBytes2Mod },                      // FCLEX, etc.
    { 0xDC, ENTRY_CopyBytes2Mod },                      // FADD/0, etc.
    { 0xDD, ENTRY_CopyBytes2Mod },                      // FFREE, etc.
    { 0xDE, ENTRY_CopyBytes2Mod },                      // FADDP, etc.
    { 0xDF, ENTRY_CopyBytes2Mod },                      // FBLD/4, etc.
    { 0xE0, ENTRY_CopyBytes2CantJump },                 // LOOPNE cb
    { 0xE1, ENTRY_CopyBytes2CantJump },                 // LOOPE cb
    { 0xE2, ENTRY_CopyBytes2CantJump },                 // LOOP cb
    { 0xE3, ENTRY_CopyBytes2Jump },                     // JCXZ/JECXZ
    { 0xE4, ENTRY_CopyBytes2 },                         // IN ib
    { 0xE5, ENTRY_CopyBytes2 },                         // IN id
    { 0xE6, ENTRY_CopyBytes2 },                         // OUT ib
    { 0xE7, ENTRY_CopyBytes2 },                         // OUT ib
    { 0xE8, ENTRY_CopyBytes3Or5Target },                // CALL cd
    { 0xE9, ENTRY_CopyBytes3Or5Target },                // JMP cd
    { 0xEA, ENTRY_CopyBytes5Or7Dynamic },               // JMP cp
    { 0xEB, ENTRY_CopyBytes2Jump },                     // JMP cb
    { 0xEC, ENTRY_CopyBytes1 },                         // IN ib
    { 0xED, ENTRY_CopyBytes1 },                         // IN id
    { 0xEE, ENTRY_CopyBytes1 },                         // OUT
    { 0xEF, ENTRY_CopyBytes1 },                         // OUT
    { 0xF0, ENTRY_CopyBytesPrefix },                    // LOCK prefix
    { 0xF1, ENTRY_Invalid },                            //
    { 0xF2, ENTRY_CopyBytesPrefix },                    // REPNE prefix
    { 0xF3, ENTRY_CopyBytesPrefix },                    // REPE prefix
    { 0xF4, ENTRY_CopyBytes1 },                         // HLT
    { 0xF5, ENTRY_CopyBytes1 },                         // CMC
    { 0xF6, ENTRY_CopyF6 },                             // TEST/0, DIV/6
    { 0xF7, ENTRY_CopyF7 },                             // TEST/0, DIV/6
    { 0xF8, ENTRY_CopyBytes1 },                         // CLC
    { 0xF9, ENTRY_CopyBytes1 },                         // STC
    { 0xFA, ENTRY_CopyBytes1 },                         // CLI
    { 0xFB, ENTRY_CopyBytes1 },                         // STI
    { 0xFC, ENTRY_CopyBytes1 },                         // CLD
    { 0xFD, ENTRY_CopyBytes1 },                         // STD
    { 0xFE, ENTRY_CopyBytes2Mod },                      // DEC/1,INC/0
    { 0xFF, ENTRY_CopyFF },                             // CALL/2
    { 0, ENTRY_End },
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable0F[257] =
{
    { 0x00, ENTRY_CopyBytes2Mod },                      // LLDT/2, etc.
    { 0x01, ENTRY_CopyBytes2Mod },                      // INVLPG/7, etc.
    { 0x02, ENTRY_CopyBytes2Mod },                      // LAR/r
    { 0x03, ENTRY_CopyBytes2Mod },                      // LSL/r
    { 0x04, ENTRY_Invalid },                            // _04
    { 0x05, ENTRY_Invalid },                            // _05
    { 0x06, ENTRY_CopyBytes2 },                         // CLTS
    { 0x07, ENTRY_Invalid },                            // _07
    { 0x08, ENTRY_CopyBytes2 },                         // INVD
    { 0x09, ENTRY_CopyBytes2 },                         // WBINVD
    { 0x0A, ENTRY_Invalid },                            // _0A
    { 0x0B, ENTRY_CopyBytes2 },                         // UD2
    { 0x0C, ENTRY_Invalid },                            // _0C
    { 0x0D, ENTRY_CopyBytes2Mod },                      // PREFETCH
    { 0x0E, ENTRY_CopyBytes2 },                         // FEMMS
    { 0x0F, ENTRY_CopyBytes3Mod },                      // 3DNow Opcodes
    { 0x10, ENTRY_CopyBytes2Mod },                      // MOVSS MOVUPD MOVSD
    { 0x11, ENTRY_CopyBytes2Mod },                      // MOVSS MOVUPD MOVSD
    { 0x12, ENTRY_CopyBytes2Mod },                      // MOVLPD
    { 0x13, ENTRY_CopyBytes2Mod },                      // MOVLPD
    { 0x14, ENTRY_CopyBytes2Mod },                      // UNPCKLPD
    { 0x15, ENTRY_CopyBytes2Mod },                      // UNPCKHPD
    { 0x16, ENTRY_CopyBytes2Mod },                      // MOVHPD
    { 0x17, ENTRY_CopyBytes2Mod },                      // MOVHPD
    { 0x18, ENTRY_CopyBytes2Mod },                      // PREFETCHINTA...
    { 0x19, ENTRY_Invalid },                            // _19
    { 0x1A, ENTRY_Invalid },                            // _1A
    { 0x1B, ENTRY_Invalid },                            // _1B
    { 0x1C, ENTRY_Invalid },                            // _1C
    { 0x1D, ENTRY_Invalid },                            // _1D
    { 0x1E, ENTRY_Invalid },                            // _1E
    { 0x1F, ENTRY_Invalid },                            // _1F
    { 0x20, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x21, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x22, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x23, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x24, ENTRY_Invalid },                            // _24
    { 0x25, ENTRY_Invalid },                            // _25
    { 0x26, ENTRY_Invalid },                            // _26
    { 0x27, ENTRY_Invalid },                            // _27
    { 0x28, ENTRY_CopyBytes2Mod },                      // MOVAPS MOVAPD
    { 0x29, ENTRY_CopyBytes2Mod },                      // MOVAPS MOVAPD
    { 0x2A, ENTRY_CopyBytes2Mod },                      // CVPI2PS &
    { 0x2B, ENTRY_CopyBytes2Mod },                      // MOVNTPS MOVNTPD
    { 0x2C, ENTRY_CopyBytes2Mod },                      // CVTTPS2PI &
    { 0x2D, ENTRY_CopyBytes2Mod },                      // CVTPS2PI &
    { 0x2E, ENTRY_CopyBytes2Mod },                      // UCOMISS UCOMISD
    { 0x2F, ENTRY_CopyBytes2Mod },                      // COMISS COMISD
    { 0x30, ENTRY_CopyBytes2 },                         // WRMSR
    { 0x31, ENTRY_CopyBytes2 },                         // RDTSC
    { 0x32, ENTRY_CopyBytes2 },                         // RDMSR
    { 0x33, ENTRY_CopyBytes2 },                         // RDPMC
    { 0x34, ENTRY_CopyBytes2 },                         // SYSENTER
    { 0x35, ENTRY_CopyBytes2 },                         // SYSEXIT
    { 0x36, ENTRY_Invalid },                            // _36
    { 0x37, ENTRY_Invalid },                            // _37
    { 0x38, ENTRY_Invalid },                            // _38
    { 0x39, ENTRY_Invalid },                            // _39
    { 0x3A, ENTRY_Invalid },                            // _3A
    { 0x3B, ENTRY_Invalid },                            // _3B
    { 0x3C, ENTRY_Invalid },                            // _3C
    { 0x3D, ENTRY_Invalid },                            // _3D
    { 0x3E, ENTRY_Invalid },                            // _3E
    { 0x3F, ENTRY_Invalid },                            // _3F
    { 0x40, ENTRY_CopyBytes2Mod },                      // CMOVO (0F 40)
    { 0x41, ENTRY_CopyBytes2Mod },                      // CMOVNO (0F 41)
    { 0x42, ENTRY_CopyBytes2Mod },                      // CMOVB & CMOVNE (0F 42)
    { 0x43, ENTRY_CopyBytes2Mod },                      // CMOVAE & CMOVNB (0F 43)
    { 0x44, ENTRY_CopyBytes2Mod },                      // CMOVE & CMOVZ (0F 44)
    { 0x45, ENTRY_CopyBytes2Mod },                      // CMOVNE & CMOVNZ (0F 45)
    { 0x46, ENTRY_CopyBytes2Mod },                      // CMOVBE & CMOVNA (0F 46)
    { 0x47, ENTRY_CopyBytes2Mod },                      // CMOVA & CMOVNBE (0F 47)
    { 0x48, ENTRY_CopyBytes2Mod },                      // CMOVS (0F 48)
    { 0x49, ENTRY_CopyBytes2Mod },                      // CMOVNS (0F 49)
    { 0x4A, ENTRY_CopyBytes2Mod },                      // CMOVP & CMOVPE (0F 4A)
    { 0x4B, ENTRY_CopyBytes2Mod },                      // CMOVNP & CMOVPO (0F 4B)
    { 0x4C, ENTRY_CopyBytes2Mod },                      // CMOVL & CMOVNGE (0F 4C)
    { 0x4D, ENTRY_CopyBytes2Mod },                      // CMOVGE & CMOVNL (0F 4D)
    { 0x4E, ENTRY_CopyBytes2Mod },                      // CMOVLE & CMOVNG (0F 4E)
    { 0x4F, ENTRY_CopyBytes2Mod },                      // CMOVG & CMOVNLE (0F 4F)
    { 0x50, ENTRY_CopyBytes2Mod },                      // MOVMSKPD MOVMSKPD
    { 0x51, ENTRY_CopyBytes2Mod },                      // SQRTPS &
    { 0x52, ENTRY_CopyBytes2Mod },                      // RSQRTTS RSQRTPS
    { 0x53, ENTRY_CopyBytes2Mod },                      // RCPPS RCPSS
    { 0x54, ENTRY_CopyBytes2Mod },                      // ANDPS ANDPD
    { 0x55, ENTRY_CopyBytes2Mod },                      // ANDNPS ANDNPD
    { 0x56, ENTRY_CopyBytes2Mod },                      // ORPS ORPD
    { 0x57, ENTRY_CopyBytes2Mod },                      // XORPS XORPD
    { 0x58, ENTRY_CopyBytes2Mod },                      // ADDPS &
    { 0x59, ENTRY_CopyBytes2Mod },                      // MULPS &
    { 0x5A, ENTRY_CopyBytes2Mod },                      // CVTPS2PD &
    { 0x5B, ENTRY_CopyBytes2Mod },                      // CVTDQ2PS &
    { 0x5C, ENTRY_CopyBytes2Mod },                      // SUBPS &
    { 0x5D, ENTRY_CopyBytes2Mod },                      // MINPS &
    { 0x5E, ENTRY_CopyBytes2Mod },                      // DIVPS &
    { 0x5F, ENTRY_CopyBytes2Mod },                      // MASPS &
    { 0x60, ENTRY_CopyBytes2Mod },                      // PUNPCKLBW/r
    { 0x61, ENTRY_CopyBytes2Mod },                      // PUNPCKLWD/r
    { 0x62, ENTRY_CopyBytes2Mod },                      // PUNPCKLWD/r
    { 0x63, ENTRY_CopyBytes2Mod },                      // PACKSSWB/r
    { 0x64, ENTRY_CopyBytes2Mod },                      // PCMPGTB/r
    { 0x65, ENTRY_CopyBytes2Mod },                      // PCMPGTW/r
    { 0x66, ENTRY_CopyBytes2Mod },                      // PCMPGTD/r
    { 0x67, ENTRY_CopyBytes2Mod },                      // PACKUSWB/r
    { 0x68, ENTRY_CopyBytes2Mod },                      // PUNPCKHBW/r
    { 0x69, ENTRY_CopyBytes2Mod },                      // PUNPCKHWD/r
    { 0x6A, ENTRY_CopyBytes2Mod },                      // PUNPCKHDQ/r
    { 0x6B, ENTRY_CopyBytes2Mod },                      // PACKSSDW/r
    { 0x6C, ENTRY_CopyBytes2Mod },                      // PUNPCKLQDQ
    { 0x6D, ENTRY_CopyBytes2Mod },                      // PUNPCKHQDQ
    { 0x6E, ENTRY_CopyBytes2Mod },                      // MOVD/r
    { 0x6F, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x70, ENTRY_CopyBytes2Mod1 },                     // PSHUFW/r ib
    { 0x71, ENTRY_CopyBytes2Mod1 },                     // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
    { 0x72, ENTRY_CopyBytes2Mod1 },                     // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
    { 0x73, ENTRY_CopyBytes2Mod1 },                     // PSLLQ/6 ib,PSRLQ/2 ib
    { 0x74, ENTRY_CopyBytes2Mod },                      // PCMPEQB/r
    { 0x75, ENTRY_CopyBytes2Mod },                      // PCMPEQW/r
    { 0x76, ENTRY_CopyBytes2Mod },                      // PCMPEQD/r
    { 0x77, ENTRY_CopyBytes2 },                         // EMMS
    { 0x78, ENTRY_Invalid },                            // _78
    { 0x79, ENTRY_Invalid },                            // _79
    { 0x7A, ENTRY_Invalid },                            // _7A
    { 0x7B, ENTRY_Invalid },                            // _7B
    { 0x7C, ENTRY_Invalid },                            // _7C
    { 0x7D, ENTRY_Invalid },                            // _7D
    { 0x7E, ENTRY_CopyBytes2Mod },                      // MOVD/r
    { 0x7F, ENTRY_CopyBytes2Mod },                      // MOV/r
    { 0x80, ENTRY_CopyBytes3Or5Target },                // JO
    { 0x81, ENTRY_CopyBytes3Or5Target },                // JNO
    { 0x82, ENTRY_CopyBytes3Or5Target },                // JB,JC,JNAE
    { 0x83, ENTRY_CopyBytes3Or5Target },                // JAE,JNB,JNC
    { 0x84, ENTRY_CopyBytes3Or5Target },                // JE,JZ,JZ
    { 0x85, ENTRY_CopyBytes3Or5Target },                // JNE,JNZ
    { 0x86, ENTRY_CopyBytes3Or5Target },                // JBE,JNA
    { 0x87, ENTRY_CopyBytes3Or5Target },                // JA,JNBE
    { 0x88, ENTRY_CopyBytes3Or5Target },                // JS
    { 0x89, ENTRY_CopyBytes3Or5Target },                // JNS
    { 0x8A, ENTRY_CopyBytes3Or5Target },                // JP,JPE
    { 0x8B, ENTRY_CopyBytes3Or5Target },                // JNP,JPO
    { 0x8C, ENTRY_CopyBytes3Or5Target },                // JL,NGE
    { 0x8D, ENTRY_CopyBytes3Or5Target },                // JGE,JNL
    { 0x8E, ENTRY_CopyBytes3Or5Target },                // JLE,JNG
    { 0x8F, ENTRY_CopyBytes3Or5Target },                // JG,JNLE
    { 0x90, ENTRY_CopyBytes2Mod },                      // CMOVO (0F 40)
    { 0x91, ENTRY_CopyBytes2Mod },                      // CMOVNO (0F 41)
    { 0x92, ENTRY_CopyBytes2Mod },                      // CMOVB & CMOVC & CMOVNAE (0F 42)
    { 0x93, ENTRY_CopyBytes2Mod },                      // CMOVAE & CMOVNB & CMOVNC (0F 43)
    { 0x94, ENTRY_CopyBytes2Mod },                      // CMOVE & CMOVZ (0F 44)
    { 0x95, ENTRY_CopyBytes2Mod },                      // CMOVNE & CMOVNZ (0F 45)
    { 0x96, ENTRY_CopyBytes2Mod },                      // CMOVBE & CMOVNA (0F 46)
    { 0x97, ENTRY_CopyBytes2Mod },                      // CMOVA & CMOVNBE (0F 47)
    { 0x98, ENTRY_CopyBytes2Mod },                      // CMOVS (0F 48)
    { 0x99, ENTRY_CopyBytes2Mod },                      // CMOVNS (0F 49)
    { 0x9A, ENTRY_CopyBytes2Mod },                      // CMOVP & CMOVPE (0F 4A)
    { 0x9B, ENTRY_CopyBytes2Mod },                      // CMOVNP & CMOVPO (0F 4B)
    { 0x9C, ENTRY_CopyBytes2Mod },                      // CMOVL & CMOVNGE (0F 4C)
    { 0x9D, ENTRY_CopyBytes2Mod },                      // CMOVGE & CMOVNL (0F 4D)
    { 0x9E, ENTRY_CopyBytes2Mod },                      // CMOVLE & CMOVNG (0F 4E)
    { 0x9F, ENTRY_CopyBytes2Mod },                      // CMOVG & CMOVNLE (0F 4F)
    { 0xA0, ENTRY_CopyBytes2 },                         // PUSH
    { 0xA1, ENTRY_CopyBytes2 },                         // POP
    { 0xA2, ENTRY_CopyBytes2 },                         // CPUID
    { 0xA3, ENTRY_CopyBytes2Mod },                      // BT  (0F A3)
    { 0xA4, ENTRY_CopyBytes2Mod1 },                     // SHLD
    { 0xA5, ENTRY_CopyBytes2Mod },                      // SHLD
    { 0xA6, ENTRY_Invalid },                            // _A6
    { 0xA7, ENTRY_Invalid },                            // _A7
    { 0xA8, ENTRY_CopyBytes2 },                         // PUSH
    { 0xA9, ENTRY_CopyBytes2 },                         // POP
    { 0xAA, ENTRY_CopyBytes2 },                         // RSM
    { 0xAB, ENTRY_CopyBytes2Mod },                      // BTS (0F AB)
    { 0xAC, ENTRY_CopyBytes2Mod1 },                     // SHRD
    { 0xAD, ENTRY_CopyBytes2Mod },                      // SHRD
    { 0xAE, ENTRY_CopyBytes2Mod },                      // FXRSTOR/1,FXSAVE/0
    { 0xAF, ENTRY_CopyBytes2Mod },                      // IMUL (0F AF)
    { 0xB0, ENTRY_CopyBytes2Mod },                      // CMPXCHG (0F B0)
    { 0xB1, ENTRY_CopyBytes2Mod },                      // CMPXCHG (0F B1)
    { 0xB2, ENTRY_CopyBytes2Mod },                      // LSS/r
    { 0xB3, ENTRY_CopyBytes2Mod },                      // BTR (0F B3)
    { 0xB4, ENTRY_CopyBytes2Mod },                      // LFS/r
    { 0xB5, ENTRY_CopyBytes2Mod },                      // LGS/r
    { 0xB6, ENTRY_CopyBytes2Mod },                      // MOVZX/r
    { 0xB7, ENTRY_CopyBytes2Mod },                      // MOVZX/r
    { 0xB8, ENTRY_Invalid },                            // _B8
    { 0xB9, ENTRY_Invalid },                            // _B9
    { 0xBA, ENTRY_CopyBytes2Mod1 },                     // BT & BTC & BTR & BTS (0F BA)
    { 0xBB, ENTRY_CopyBytes2Mod },                      // BTC (0F BB)
    { 0xBC, ENTRY_CopyBytes2Mod },                      // BSF (0F BC)
    { 0xBD, ENTRY_CopyBytes2Mod },                      // BSR (0F BD)
    { 0xBE, ENTRY_CopyBytes2Mod },                      // MOVSX/r
    { 0xBF, ENTRY_CopyBytes2Mod },                      // MOVSX/r
    { 0xC0, ENTRY_CopyBytes2Mod },                      // XADD/r
    { 0xC1, ENTRY_CopyBytes2Mod },                      // XADD/r
    { 0xC2, ENTRY_CopyBytes2Mod },                      // CMPPS &
    { 0xC3, ENTRY_CopyBytes2Mod },                      // MOVNTI
    { 0xC4, ENTRY_CopyBytes2Mod1 },                     // PINSRW /r ib
    { 0xC5, ENTRY_CopyBytes2Mod1 },                     // PEXTRW /r ib
    { 0xC6, ENTRY_CopyBytes2Mod1 },                     // SHUFPS & SHUFPD
    { 0xC7, ENTRY_CopyBytes2Mod },                      // CMPXCHG8B (0F C7)
    { 0xC8, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xC9, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xCA, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xCB, ENTRY_CopyBytes2 },                         //CVTPD2PI BSWAP 0F C8 + rd
    { 0xCC, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xCD, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xCE, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xCF, ENTRY_CopyBytes2 },                         // BSWAP 0F C8 + rd
    { 0xD0, ENTRY_Invalid },                            // _D0
    { 0xD1, ENTRY_CopyBytes2Mod },                      // PSRLW/r
    { 0xD2, ENTRY_CopyBytes2Mod },                      // PSRLD/r
    { 0xD3, ENTRY_CopyBytes2Mod },                      // PSRLQ/r
    { 0xD4, ENTRY_CopyBytes2Mod },                      // PADDQ
    { 0xD5, ENTRY_CopyBytes2Mod },                      // PMULLW/r
    { 0xD6, ENTRY_CopyBytes2Mod },                      // MOVDQ2Q / MOVQ2DQ
    { 0xD7, ENTRY_CopyBytes2Mod },                      // PMOVMSKB/r
    { 0xD8, ENTRY_CopyBytes2Mod },                      // PSUBUSB/r
    { 0xD9, ENTRY_CopyBytes2Mod },                      // PSUBUSW/r
    { 0xDA, ENTRY_CopyBytes2Mod },                      // PMINUB/r
    { 0xDB, ENTRY_CopyBytes2Mod },                      // PAND/r
    { 0xDC, ENTRY_CopyBytes2Mod },                      // PADDUSB/r
    { 0xDD, ENTRY_CopyBytes2Mod },                      // PADDUSW/r
    { 0xDE, ENTRY_CopyBytes2Mod },                      // PMAXUB/r
    { 0xDF, ENTRY_CopyBytes2Mod },                      // PANDN/r
    { 0xE0, ENTRY_CopyBytes2Mod  },                     // PAVGB
    { 0xE1, ENTRY_CopyBytes2Mod },                      // PSRAW/r
    { 0xE2, ENTRY_CopyBytes2Mod },                      // PSRAD/r
    { 0xE3, ENTRY_CopyBytes2Mod },                      // PAVGW
    { 0xE4, ENTRY_CopyBytes2Mod },                      // PMULHUW/r
    { 0xE5, ENTRY_CopyBytes2Mod },                      // PMULHW/r
    { 0xE6, ENTRY_CopyBytes2Mod },                      // CTDQ2PD &
    { 0xE7, ENTRY_CopyBytes2Mod },                      // MOVNTQ
    { 0xE8, ENTRY_CopyBytes2Mod },                      // PSUBB/r
    { 0xE9, ENTRY_CopyBytes2Mod },                      // PSUBW/r
    { 0xEA, ENTRY_CopyBytes2Mod },                      // PMINSW/r
    { 0xEB, ENTRY_CopyBytes2Mod },                      // POR/r
    { 0xEC, ENTRY_CopyBytes2Mod },                      // PADDSB/r
    { 0xED, ENTRY_CopyBytes2Mod },                      // PADDSW/r
    { 0xEE, ENTRY_CopyBytes2Mod },                      // PMAXSW /r
    { 0xEF, ENTRY_CopyBytes2Mod },                      // PXOR/r
    { 0xF0, ENTRY_Invalid },                            // _F0
    { 0xF1, ENTRY_CopyBytes2Mod },                      // PSLLW/r
    { 0xF2, ENTRY_CopyBytes2Mod },                      // PSLLD/r
    { 0xF3, ENTRY_CopyBytes2Mod },                      // PSLLQ/r
    { 0xF4, ENTRY_CopyBytes2Mod },                      // PMULUDQ/r
    { 0xF5, ENTRY_CopyBytes2Mod },                      // PMADDWD/r
    { 0xF6, ENTRY_CopyBytes2Mod },                      // PSADBW/r
    { 0xF7, ENTRY_CopyBytes2Mod },                      // MASKMOVQ
    { 0xF8, ENTRY_CopyBytes2Mod },                      // PSUBB/r
    { 0xF9, ENTRY_CopyBytes2Mod },                      // PSUBW/r
    { 0xFA, ENTRY_CopyBytes2Mod },                      // PSUBD/r
    { 0xFB, ENTRY_CopyBytes2Mod },                      // FSUBQ/r
    { 0xFC, ENTRY_CopyBytes2Mod },                      // PADDB/r
    { 0xFD, ENTRY_CopyBytes2Mod },                      // PADDW/r
    { 0xFE, ENTRY_CopyBytes2Mod },                      // PADDD/r
    { 0xFF, ENTRY_Invalid },                            // _FF
    { 0, ENTRY_End },
};

BOOL CDetourDis::SanityCheckSystem()
{
    ULONG n = 0;
    for (; n < 256; n++) {
        REFCOPYENTRY pEntry = &s_rceCopyTable[n];

        if (n != pEntry->nOpcode) {
            ASSERT(n == pEntry->nOpcode);
            return FALSE;
        }
    }
    if (s_rceCopyTable[256].pfCopy != NULL) {
        ASSERT(!"Missing end marker.");
        return FALSE;
    }

    for (n = 0; n < 256; n++) {
        REFCOPYENTRY pEntry = &s_rceCopyTable0F[n];

        if (n != pEntry->nOpcode) {
            ASSERT(n == pEntry->nOpcode);
            return FALSE;
        }
    }
    if (s_rceCopyTable0F[256].pfCopy != NULL) {
        ASSERT(!"Missing end marker.");
        return FALSE;
    }

    return TRUE;
}
#endif // defined(DETOURS_X64) || defined(DETOURS_X86)

/////////////////////////////////////////////////////////// IA64 Disassembler.
//
#ifdef DETOURS_IA64
#error Feature not supported in this release.






































































































































































































































































































































































































































































































































#endif // DETOURS_IA64

//
///////////////////////////////////////////////////////////////// End of File.
