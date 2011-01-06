#include "stdafx.h"

#include <windows.h>

#include ".\..\Redirector.h"
#include ".\..\CMMN.h"

//
//	By Pavels
//
//	This application is used for redirection data from the console to the pipes, 
//	not useng pipes at the other side.
//	It is caused by some differences when using some other proceses which
//	also redirect data. Main reason is differences in ReadConsole and ReadFile
//	methods.
//	Using this redirector app, child process will never know that his parent redirects it's IO.
//
//	Everything is asynchronous. 3 Threads.
//

int _tmain(int argc, _TCHAR* argv[])
{
	CLogger::LogLine(TEXT("TIOR: Hello"));

	TRedirectorPair in = {0};
	in.Source = CreateFile( STDIn_PIPE, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, 0);
	//in.KeepAlive = true;
	in.Name.assign(TEXT("TIOR: [in]"));
	if ( INVALID_HANDLE_VALUE != in.Source )
	{
		in.Destination = GetStdHandle( STD_INPUT_HANDLE );
		in.DestinationConsole = true;
		if (  INVALID_HANDLE_VALUE != in.Destination )
			in.Thread  = CreateThread( NULL , 0, Redirector, (LPVOID)&in, 0, NULL);
	}

	TRedirectorPair out = {0};
	out.Destination = CreateFile( STDOut_PIPE, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, 0);
	out.KeepAlive = true;
	out.Name.assign(TEXT("TIOR: [out]"));
	if ( INVALID_HANDLE_VALUE != out.Destination )
	{
		SECURITY_ATTRIBUTES sa;
		sa.nLength= sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;

		HANDLE tmp; 
		CreatePipe(&out.Source,&tmp,&sa,0);
		SetStdHandle( STD_OUTPUT_HANDLE, tmp );
		out.Thread  = CreateThread( NULL , 0, Redirector, (LPVOID)&out, 0, NULL);
	}

	TRedirectorPair err = {0};
	err.Destination = CreateFile( STDErr_PIPE, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, 0);
	err.KeepAlive = true;
	err.Name.assign(TEXT("TIOR: [err]"));
	if ( INVALID_HANDLE_VALUE != err.Destination )
	{
		SECURITY_ATTRIBUTES sa;
		sa.nLength= sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;

		HANDLE tmp; 
		CreatePipe(&err.Source,&tmp,&sa,0);
		SetStdHandle( STD_ERROR_HANDLE, tmp );
		err.Thread  = CreateThread( NULL , 0, Redirector, (LPVOID)&err, 0, NULL);
	}

	///////////////////////////////////////////////////////////////////////////////////

	//
	//	Obtainig information about process to start and redirect
	//

	std::wstring shell, args, dir;
	CInterprocessStorage::GetString( TEXT("w7e_TIORShell"), shell );
	CInterprocessStorage::GetString( TEXT("w7e_TIORArgs"), args );
	CInterprocessStorage::GetString( TEXT("w7e_TIORDir"), dir );

	CLogger::LogLine(TEXT("TIOR: shell="));	CLogger::LogLine(shell);
	CLogger::LogLine(TEXT("TIOR: args="));	CLogger::LogLine(args);
	CLogger::LogLine(TEXT("TIOR: dir="));	CLogger::LogLine(dir);

	STARTUPINFO si = {0};si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {0};

	BOOL created = CreateProcess( 
		shell.c_str(), 
		const_cast<TCHAR *>(args.c_str()), 
		NULL, 
		NULL, 
		TRUE, 
		0, 
		NULL, 
		dir.c_str(), 
		&si, 
		&pi );

	if ( ! created )
	{
		CLogger::LogLine(
			CError::Format(
				GetLastError(), 
				TEXT("TIOR: Unable to create child process"), 
				TEXT("CreateProcess")));

		return EXIT_FAILURE;
	}
	else
	{
		CloseHandle( pi.hThread );
	}

	CLogger::LogLine(TEXT("TIOR: Shell has been started. Waiting..."));
	HANDLE waiters[4] = {pi.hProcess, in.Thread, out.Thread, err.Thread} ;
	//
	//	Waiting for eny handle to be freed. 
	//	Either some IO thread will die or process will be oevered.
	//
	WaitForMultipleObjects( 4, waiters, FALSE, INFINITE );
	CLogger::LogLine(TEXT("TIOR: Ensure that we processed all data in pipes"));

	//
	//	Even if process was overed, we need to be sure that we readed all data from the redirected pipe.
	//	Thats why we wait again for some period of time reading died process's output untill the end.
	//
	WaitForMultipleObjects( 3, waiters + 1, FALSE, 1000 );

	//
	//	Dont forget to close child process. We need to be sure, if user terminated app which
	//	reads our redirected data, we terminate the target child app.
	//
	CLogger::LogLine(TEXT("TIOR: Killing child process"));
	TerminateProcess( pi.hProcess, EXIT_FAILURE );
	CloseHandle( pi.hProcess );

	CLogger::LogLine(TEXT("TIOR: Exit"));

	//
	//	I will not close any handles here - system will terminate and close all by it self.
	//

	return EXIT_SUCCESS;
}

