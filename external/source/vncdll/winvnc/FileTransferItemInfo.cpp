//  Copyright (C) 2003 Dennis Syrovatsky. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
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
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.

#include "FileTransferItemInfo.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

FileTransferItemInfo::FileTransferItemInfo()
{
	m_NumEntries = 0;
	m_pEntries = NULL;
}

FileTransferItemInfo::~FileTransferItemInfo()
{
	Free();
}

void FileTransferItemInfo::Add(char *Name, unsigned int Size, unsigned int Data)
{
	FTITEMINFO *pTemporary = new FTITEMINFO[m_NumEntries + 1];
	if (m_NumEntries != 0) 
		memcpy(pTemporary, m_pEntries, m_NumEntries * sizeof(FTITEMINFO));
	strcpy(pTemporary[m_NumEntries].Name, Name);
	pTemporary[m_NumEntries].Size = Size;
	pTemporary[m_NumEntries].Data = Data;
	if (m_pEntries != NULL) {
		delete [] m_pEntries;
		m_pEntries = NULL;
	}
	m_pEntries = pTemporary;
	pTemporary = NULL;
	m_NumEntries++;
}

void FileTransferItemInfo::Free()
{
	if (m_pEntries != NULL) {
		delete [] m_pEntries;
		m_pEntries = NULL;
	}
	m_NumEntries = 0;
}

char * FileTransferItemInfo::GetNameAt(int Number)
{
	if ((Number >= 0) && (Number <= m_NumEntries))
		return m_pEntries[Number].Name;
	return NULL;
}

unsigned int FileTransferItemInfo::GetSizeAt(int Number)
{
	if ((Number >= 0) && (Number <= m_NumEntries)) 
		return m_pEntries[Number].Size; 
	return NULL;
}

unsigned int FileTransferItemInfo::GetDataAt(int Number)
{
	if ((Number >= 0) && (Number <= m_NumEntries)) 
		return m_pEntries[Number].Data; 
	return NULL;
}

int FileTransferItemInfo::GetNumEntries()
{
	return m_NumEntries;
}

int FileTransferItemInfo::GetSummaryNamesLength()
{
	size_t sumLen = 0;
	for (int i = 0; i < m_NumEntries; i++)
		sumLen += strlen(m_pEntries[i].Name);
	return (int)sumLen;
}
