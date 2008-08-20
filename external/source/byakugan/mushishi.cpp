#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#include "byakugan.h"
#include "mushishi.h"
#include "stdwindbg.h"

#define CRUSH_DR_CONTEXT "e esp+0x34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00; g"
#define REWRITE_IMAGE_SIZE "t; ed 0x%08x 0x%08x; g;"

ULONG originalImageSize;

BOOL maskHardwareBreaks(void) {
	ULONG64				funcAddr64;
	PDEBUG_BREAKPOINT	bp;

	if ((funcAddr64 = resolveFunctionByName("RtlDispatchException")) == NULL)
		return (FALSE);
	g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
	bp->SetCommand(CRUSH_DR_CONTEXT);
	bp->SetOffset(funcAddr64);
	bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	return (TRUE);
}

// FIXME
BOOL DetectHardwareBreakCheck(void) {
    ULONG64             funcAddr64;
    PDEBUG_BREAKPOINT   bp;

    if ((funcAddr64 = resolveFunctionByName("RtlDispatchException")) == NULL)
        return (FALSE);
    g_ExtControl->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
    bp->SetCommand(CRUSH_DR_CONTEXT);
    bp->SetOffset(funcAddr64);
    bp->SetFlags(DEBUG_BREAKPOINT_ENABLED);

    return (TRUE);
}

ULONG64	getPointerToImageSize() {
	ULONG64	ptr;

	ptr = GetExpression("poi(poi(poi(fs:[0x30]) + 0xC) + 0xC)");
	ptr += 0x20;

	return (ptr);
}

BOOL protectImageSize() {
	ULONG64				imageSizePtr;
	PDEBUG_BREAKPOINT	bp;
	char				rewriteCommand[64];

	imageSizePtr = getPointerToImageSize();
	
	memset(rewriteCommand, 0, 64);
	_snprintf_s(rewriteCommand, 64 - 1, "poi(0x%08x)", imageSizePtr);
	originalImageSize = GetExpression(rewriteCommand);
	dprintf("[Mushishi] Original Image Size: 0x%08x\n", originalImageSize);
	
	bp = detectWriteByAddr(imageSizePtr, "overwrite of PEB image size");
	memset(rewriteCommand, 0, 64);
	_snprintf_s(rewriteCommand, 64 - 1, REWRITE_IMAGE_SIZE, imageSizePtr, originalImageSize);
	bp->SetCommand(rewriteCommand);

	return (TRUE);
}

BOOL detectImageSizeOverwrite() {
    ULONG64				imageSizePtr;
	PDEBUG_BREAKPOINT	bp;

	imageSizePtr = getPointerToImageSize();
	dprintf("[Mushishi] ImageSize found at 0x%08x\n", imageSizePtr);
	bp = detectWriteByAddr(imageSizePtr, "overwrite of PEB image size");
	
	return (TRUE);
}

void mushishiDetect(void) {

	// 1)  Check for a call to CheckRemoteDebuggerPresent
	detectCallByName("CheckRemoteDebuggerPresent", "CheckRemoteDebuggerPresent");
	
	// 2)  Check for reading of the dr0-dr3 section of CONTEXT structs
	//DetectHardwareBreakCheck();

	// 3)  Check for a call to OutputDebugString which is sensitive to an attached debugger
	detectCallByName("OutputDebugString", "OutputDebugString");

	// 4)  Check for an overwrite of the image size
	detectImageSizeOverwrite();

	// 5) Check for setLastError
	detectCallByName("SetLastError", "SetLastError");
}

void mushishiDefeat(void) {
    // 1) Call CheckRemoteDebuggerPresent to detect attached debugger
	// Disable the check for remote debugger
    if (disableFunctionFalse("CheckRemoteDebuggerPresent") == FALSE)
        dprintf("[Mushishi] Unable to disable \"CheckRemoteDebuggerPresent\" function!\n");

	// 2) Force a hardware exception, then check the SEH CONTEXT to see if dr0-dr3 are set
    // Clear hardware breakpoints from SEH CONTEXT
	if (maskHardwareBreaks() == FALSE)
        dprintf("[Mushishi] Unable to disable Hardware Breakpoint checks from CONTEXT!\n");

	// 3) 
	if (protectImageSize() == FALSE)
		dprintf("[Mushishi] Unable to protect the image size!\n");
}
