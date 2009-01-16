#include "byakugan.h"
#include "msfpattern.h"
#include "jutsu.h"
#include "tenketsu.h"
#include "mushishi.h"
#include "symPort.h"

char *registers[] = {
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esp",
    "ebp",
    "eip",
    NULL
};

HRESULT CALLBACK byakugan(PDEBUG_CLIENT4 Client, PCSTR args) {
    INIT_API();
    UNREFERENCED_PARAMETER(args);
    
    dprintf(HELPSTRING);
    dprintf("!jutsu <command> <args> - Perform Jutsu: !jutsu help\n");
	dprintf("!tenketsu - Begin realtime heap vizualization: !tenketsu help\n");
    dprintf("!pattern_offset <length> <optional: addr>\n");
	dprintf("!mushishi <detect|defeat>- Detect or defeat anti-debugging mechanisms\n");

    EXIT_API();
    return (S_OK);
}

HRESULT CALLBACK pattern_offset(PDEBUG_CLIENT4 Client, PCSTR args) {
    char    *arg1, **arg2, *holder[2], *context;
    ULONG   length, addr;
    int     offset, i;
    
    INIT_API();
    UNREFERENCED_PARAMETER(args);    

    arg1 = strtok((char *)args, " ");
    arg2 = holder;
    arg2[0] = strtok(NULL, " ");
    arg2[1] = NULL;

    if (arg1 == NULL) {
        dprintf("[Byakugan] Please provide a length.\n");
        return (S_OK);
    }

    length = strtoul(arg1, NULL, 10);
   
    if (arg2[0] == NULL) 
        arg2 = registers;

    for (i = 0; arg2[i] != NULL; i++) {
        addr = GetExpression(arg2[i]);

        offset = msf_pattern_offset(length, addr);
        if (offset != -1) 
            dprintf("[Byakugan] Control of %s at offset %d.\n", arg2[i], offset);
    }

    EXIT_API();
    return (S_OK);
}

HRESULT CALLBACK mushishi(PDEBUG_CLIENT4 Client, PCSTR args) {
	char	*command;
	
	INIT_API();

	command = strtok((char *)args, " ");
    if (command != NULL) {
        if (!_stricmp(command, "detect")) {
            mushishiDetect();
            return (S_OK);
        }
        if (!_stricmp(command, "defeat")) {
            mushishiDefeat();
			return (S_OK);
        }
	}
	dprintf("[Mushishi] Proper commands are: 'detect' 'defeat'\n");

	EXIT_API();
	return (S_OK);
}

HRESULT CALLBACK symport(PDEBUG_CLIENT4 Client, PCSTR args) {
    char    *command, *module, *path;
    
    INIT_API();

    module	= strtok((char *)args, " ");
	path	= strtok(NULL, " ");
    if (module != NULL && path != NULL) {
			addMapFile(module, path);
            return (S_OK);
    } else {
		dprintf("[symPort] Proper format is: !symport <moduleName> <map file path>\n");
	}
    EXIT_API();
    return (S_OK);
}

HRESULT CALLBACK jutsu(PDEBUG_CLIENT4 Client, PCSTR args) {
    char    *command, *bufName, *bufPatt, *bindPort, *bufSize, *bufType, *bufAddr;

    INIT_API();
    
	command = strtok((char *)args, " ");
    if (command != NULL) {
		if (!_stricmp(command, "help")) {
			helpJutsu();
			return (S_OK);
		}
		if (!_stricmp(command, "memDiff")) {
			bufType = strtok(NULL, " ");
			bufSize = strtok(NULL, " ");
			bufPatt = strtok(NULL, " ");
			bufAddr	= strtok(NULL, " ");
			if (!bufAddr) {
				dprintf("[J] Format: memDiff <type> <size> <value> <address>\n");
				dprintf("Valid Types:\n\thex: Value is any hex characters\n");
				dprintf("\tfile: Buffer is read in from file at path <value>\n");
				dprintf("\tbuf: Buffer is taken from known tracked Buffers\n");
				return (S_OK);
			}
			memDiffJutsu(bufType, strtoul(bufSize, NULL, 10), 
						bufPatt, strtoul(bufAddr, NULL, 0x10));
		}
		if (!_stricmp(command, "trackVal")) {
			bufName = strtok(NULL, " ");
			bufSize = strtok(NULL, " ");
			bufPatt = strtok(NULL, " ");
			
			if (bufName == NULL) {
				listTrackedVals();
			} else if (bufSize == NULL) {
				listTrackedValByName(bufName);
			} else
				trackValJutsu(bufName, strtoul(bufSize, NULL, 10), 
						strtoul(bufPatt, NULL, 0x10));
		}
		if (!_stricmp(command, "searchOpcode")) {
			char	*instructions;
			
			instructions = (char *) args + strlen(command) + 1;
			searchOpcodes(instructions);
			return (S_OK);
		}
		if (!_stricmp(command, "listen")) {
			bindPort = strtok(NULL, " ");
			if (bindPort == NULL)
				bindPort = DEFAULT_PORT;
			bindJutsu(bindPort);
			return (S_OK);
		}
		if (!_stricmp(command, "listBuf")) {
			listTrackedBufJutsu();
			return (S_OK);
		}
		if (!_stricmp(command, "listReqs")) {
			showRequestsJutsu();
			return (S_OK);
		}
		if (!_stricmp(command, "rmBuf")) {
			bufName = strtok(NULL, " ");
			if (bufName == NULL) {
				dprintf("[Byakugan] This command requires a buffer name\n");
				return (S_OK);
			}
			rmBufJutsu(bufName);
			return (S_OK);
		}
		if (!_stricmp(command, "identBuf")) {

			bufType = strtok(NULL, " ");
			bufName = strtok(NULL, " ");
			bufPatt = strtok(NULL, " ");
			bufSize = strtok(NULL, " ");
			if (bufPatt == NULL) {
				dprintf("[Byakugan] This command requires a buffer type, name, (sometimes) value, and size\n");
				return (S_OK);
			}
			identBufJutsu(bufType, bufName, bufPatt, strtoul(bufSize, NULL, 10));
			return (S_OK);
		}
		if (!_stricmp(command, "hunt")) {
			hunterJutsu();
		}

		if (!_stricmp(command, "findReturn")) {
			returnAddressHuntJutsu();
		}
	}
    EXIT_API();
	return (S_OK);
}
HRESULT CALLBACK tenketsu(PDEBUG_CLIENT4 Client, PCSTR args) {
	char    *command, *heapName;
	PVOID	heapHandle;
	
	INIT_API();
    
    command = strtok((char *)args, " ");
	
	if (command == NULL) {
    	if(hookRtlHeap()) {
        	dprintf("[Byakugan] Unable to begin realtime heap debugging.\n");
            EXIT_API();
        	return (S_FALSE);
    	}
	}
    else if (!_stricmp(command, "help")) {
		tenkHelp();
		return (S_OK);
	}
    else if (!_stricmp(command, "validate")) {
        heapName = strtok(NULL, " ");
        if (heapName == NULL) {
            dprintf("[Byakugan] Please provide a heap handle.\n");
            return (S_OK);
        }
        heapHandle = (PVOID) strtoul(heapName, NULL, 16);
		tenkValidate(heapHandle);
		return (S_OK);
	}
	else if (!_stricmp(command, "listHeaps")) {
		tenkListHeaps();
		return (S_OK);
	}
    else if (!_stricmp(command, "listChunks")) {
		heapName = strtok(NULL, " ");
		if (heapName == NULL) {
			dprintf("[Byakugan] Please provide a heap handle.\n");
			return (S_OK);
		}
		heapHandle = (PVOID) strtoul(heapName, NULL, 16);
		tenkListChunks(heapHandle);
		return (S_OK);
	}

	EXIT_API();

	return (S_OK);
}
