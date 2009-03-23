//  Copyright (C) 2002-2003 RealVNC Ltd. All Rights Reserved.
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// If the source code for the program is not available from the place from
// which you received this file, check http://www.realvnc.com/ or contact
// the authors on info@realvnc.com for information on obtaining it.

// Log.cpp: implementation of the VNCLog class.
//
//////////////////////////////////////////////////////////////////////

#include "stdhdrs.h"
#include <io.h>
#include "vnclog.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

const int VNCLog::ToDebug   =  1;
const int VNCLog::ToFile    =  2;
const int VNCLog::ToConsole =  4;

const static int LINE_BUFFER_SIZE = 1024;

VNCLog::VNCLog()
{
	m_lastLogTime = 0;
	m_filename = "c:\\vncdll.log";
	m_append = false;
    hlogfile = NULL;
    m_todebug = false;
    m_toconsole = false;
    m_tofile = false;
}

void VNCLog::SetMode(int mode) {
    
    if (mode & ToDebug)
        m_todebug = true;
    else
        m_todebug = false;

    if (mode & ToFile)  {
		if (!m_tofile)
			OpenFile();
	} else {
		CloseFile();
        m_tofile = false;
    }
    
    if (mode & ToConsole) {
        if (!m_toconsole) {
            AllocConsole();
            fclose(stdout);
            fclose(stderr);
            int fh = _open_osfhandle((long)GetStdHandle(STD_OUTPUT_HANDLE), 0);
            _dup2(fh, 1);
            _dup2(fh, 2);
            _fdopen(1, "wt");
            _fdopen(2, "wt");
            printf("fh is %d\n",fh);
            fflush(stdout);
        }

        m_toconsole = true;

    } else {
        m_toconsole = false;
    }
}


void VNCLog::SetLevel(int level) {
    m_level = level;
}

void VNCLog::SetFile(const char* filename, bool append) 
{
	if (m_filename != NULL)
		free(m_filename);
	m_filename = strdup(filename);
	m_append = append;
	if (m_tofile)
		OpenFile();
}

void VNCLog::OpenFile()
{
	// Is there a file-name?
	if (m_filename == NULL)
	{
        m_todebug = true;
        m_tofile = false;
        Print(0, "Error opening log file\n");
		return;
	}

    m_tofile  = true;
    
	// If there's an existing log and we're not appending then move it
	if (!m_append)
	{
		// Build the backup filename
		char *backupfilename = new char[strlen(m_filename)+5];
		if (backupfilename)
		{
			strcpy(backupfilename, m_filename);
			strcat(backupfilename, ".bak");
			// Attempt the move and replace any existing backup
			// Note that failure is silent - where would we log a message to? ;)
			MoveFileEx(m_filename, backupfilename, MOVEFILE_REPLACE_EXISTING);
			delete [] backupfilename;
		}
	}

	CloseFile();

    // If filename is NULL or invalid we should throw an exception here
    hlogfile = CreateFile(
        m_filename,  GENERIC_WRITE, FILE_SHARE_READ, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL  );
    
    if (hlogfile == INVALID_HANDLE_VALUE) {
        // We should throw an exception here
        m_todebug = true;
        m_tofile = false;
        Print(0, "Error opening log file %s\n", m_filename);
    }
    if (m_append) {
        SetFilePointer( hlogfile, 0, NULL, FILE_END );
    } else {
        SetEndOfFile( hlogfile );
    }
}

// if a log file is open, close it now.
void VNCLog::CloseFile() {
    if (hlogfile != NULL) {
        CloseHandle(hlogfile);
        hlogfile = NULL;
    }
}

inline void VNCLog::ReallyPrintLine(const char* line) 
{
    if (m_todebug) OutputDebugString(line);
    if (m_toconsole) {
        DWORD byteswritten;
        WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), line, strlen(line), &byteswritten, NULL); 
    };
    if (m_tofile && (hlogfile != NULL)) {
        DWORD byteswritten;
        WriteFile(hlogfile, line, strlen(line), &byteswritten, NULL); 
    }
}

void VNCLog::ReallyPrint(const char* format, va_list ap) 
{
	time_t current = time(0);
	if (current != m_lastLogTime) {
		m_lastLogTime = current;
		ReallyPrintLine(ctime(&m_lastLogTime));
	}

	// - Write the log message, safely, limiting the output buffer size
	TCHAR line[LINE_BUFFER_SIZE];
    _vsnprintf(line, LINE_BUFFER_SIZE, format, ap);
	ReallyPrintLine(line);
}

VNCLog::~VNCLog()
{
	if (m_filename != NULL)
		free(m_filename);
    CloseFile();
}
