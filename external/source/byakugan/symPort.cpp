#include "byakugan.h"
#include "symport.h"

HRESULT addSymbol(ULONG64 address, char *symbolName) {
	HRESULT		retVal;
	if (S_OK != (retVal = g_ExtSymbols->AddSyntheticSymbol(address, 1, 
										symbolName, DEBUG_ADDSYNTHSYM_DEFAULT, NULL))) {
		dprintf("[S] Failed to add synthetic symbol: %s\n", symbolName);
		return (-1);
	}
	
	printf("[S] Successfully added symbol!\n");
	return (S_OK);
}

ULONG64 getBase(char *imageName) {
	ULONG64		baseAddress;
	DWORD		index;
	
	if (S_OK != g_ExtSymbols->GetModuleByModuleName2(imageName, 0, 0, &index, &baseAddress))
		return (0);
	return (baseAddress);
}

void parseMapLine(char *mapBuf, ULONG64 *symAddress, char **symbolName, BYTE *state) {
	char	*startAddr;
	DWORD	lineLen = strlen(mapBuf);

	if (*state & MAP_STATE_ENTRYPOINT) 
		return;
	if (*state & MAP_STATE_LOCALSYM) {
		// parse up local symbol section
		if (strstr(mapBuf, "Program entry")) {
			*state |= MAP_STATE_ENTRYPOINT;
			return;
		}
		
		// MEAT OF THE FUNCTION - Get the Addr and Name from the line
		if ((startAddr = strchr(mapBuf, ':')) == NULL)
			return;
		if ((startAddr - mapBuf + 10) > lineLen) {
			dprintf("[S] Malformed map line: %s\n", mapBuf);
			return;
		}
		startAddr[9] = '\x00';
		*symAddress = _strtoui64(startAddr+1, NULL, 16);
		
		startAddr += 10;
		while (*startAddr == ' ' && (startAddr - mapBuf) < lineLen)
			startAddr++;
		if ((startAddr - mapBuf) >= lineLen) {
			dprintf("[S] Malformed map line: %s\n", mapBuf);
			return;
		}

		*symbolName = startAddr;
		startAddr = strchr(*symbolName, '\n');
		if (startAddr)
			*startAddr = '\x00';

	} else if (!(*state)) {
		// Look for start of LOCALSYM section
		if (strstr(mapBuf, "Publics by Value"))
			*state |= MAP_STATE_LOCALSYM;
	}
}

HRESULT addMapFile(char *imageName, char *mapPath) {
	HANDLE		mapFile;
	DWORD		readOut = 1, i = 0, symCount = 0;
	ULONG64		symAddress, imageBase;
	char		mapBuf[MAP_BUF_SIZE+1], *symbolName = NULL, out = ' ';
	BYTE		state = 0;

	if (0 == (imageBase = getBase(imageName))) {
		dprintf("[S] Failed to get base address for module %s\n", imageName);
		return (-1);
	}
	dprintf("[S] Adjusting symbols to base address of: 0x%16y\n", imageBase);

	if((mapFile = CreateFile(mapPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		dprintf("[S] Unable to open map file: %s\n", mapPath);
		return (-1);
	}
	
	while (readOut > 0 && i < MAP_BUF_SIZE) {
		ReadFile(mapFile, &out, 1, &readOut, NULL);
		if (out == '\n') {
			mapBuf[i] = '\x00';
			i = 0;
			parseMapLine(mapBuf, &symAddress, &symbolName, &state);
			symAddress += imageBase;
			if (symbolName != NULL) {
				//dprintf("Addr: 0x%16y\tName: %s\n", symAddress, symbolName);
				if (S_OK == addSymbol(symAddress, symbolName))
					symCount++;
				symAddress = 0; symbolName = NULL;
			}
		} else {
			mapBuf[i++] = out;
		}
	}
	dprintf("[S] Successfully imported %d symbols.\n", symCount);
	return (S_OK);
}
