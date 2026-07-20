#include "stdafx.h"
#include "ReflectiveFree.h"
#include <Windows.h>

typedef NTSTATUS
(NTAPI *NtQueueApcThread)(
    HANDLE    ThreadHandle,
    PVOID     ApcRoutine,
    ULONG_PTR SystemArgument1,
    ULONG_PTR SystemArgument2,
    ULONG_PTR SystemArgument3
    );

VOID ReflectiveFree(HINSTANCE hAppInstance) {
    NtQueueApcThread pNtQueueApcThread = (NtQueueApcThread)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtQueueApcThread");
    HANDLE hThread = NULL;
    HANDLE hThisThread = NULL;
    do {
        if (!pNtQueueApcThread)
            break;

        // create a suspended thread that will just exit once the APCs have executed
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitThread, 0, CREATE_SUSPENDED, NULL);
        if (!hThread)
            break;

        // open a real handle to this thread to pass in the APC so it operates on this thread and not itself
        hThisThread = OpenThread(THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentThreadId());
        if (!hThisThread)
        {
            break;
        }


        // The other thread will:
        // - Wait for us: WaitForSingleObjectEx(hThisThread, INFINITE, FALSE);
        // - Close the handle we opened: CloseHandle(hThisThread);
        // - Free the memory: VirtualFree(hAppInstance, 0, MEM_RELEASE);

        // tell that thread to wait on this thread, ensures VirtualFree isn't called until this thread has exited
        NTSTATUS status = pNtQueueApcThread(hThread, WaitForSingleObjectEx, (ULONG_PTR)hThisThread, INFINITE, FALSE);

        // then close the handle so it's not leaked
        QueueUserAPC((PAPCFUNC)CloseHandle, hThread, (ULONG_PTR)hThisThread);
        // then free the memory
        status = pNtQueueApcThread(hThread, VirtualFree, (ULONG_PTR)hAppInstance, 0, MEM_RELEASE);
        ResumeThread(hThread);
    } while (FALSE);

    if (hThread)
    {
        CloseHandle(hThread);
    }
}

VOID ReflectiveFreeAndExitThread(HINSTANCE hAppInstance, DWORD dwExitCode) {
    ReflectiveFree(hAppInstance);

    ExitThread(dwExitCode);
    return;
}