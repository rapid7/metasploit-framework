#include "byakugan.h"
#include "msfpattern.h"
#include "jutsu.h"
#include "tenketsu.h"
#include "mushishi.h"
#include "symPort.h"

#include "csv_parser.hpp"
#include <ios>
#include <iostream>
#include <sstream>

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
	using namespace std;
    INIT_API();
    
	command = strtok((char *)args, " ");
    if (command != NULL) {
		if (!_stricmp(command, "help")) {
			helpJutsu();
			return (S_OK);
		}
		if (!_stricmp(command, "moduleInfo")) {

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
		if (!_stricmp(command, "searchVtptr")) {
            char    *instructions, *offsetString;
			DWORD	offset;
			
			offsetString = strtok(NULL, " ");
			offset = strtoul(offsetString, NULL, 16);
            instructions = offsetString + strlen(offsetString) + 1;
            searchVtptr(offset, instructions);
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
            if (bufSize == NULL)
                identBufJutsu(bufType, bufName, bufPatt, 0, 0);
            else
                identBufJutsu(bufType, bufName, bufPatt, strtoul(bufSize, NULL, 10), 0);
            return (S_OK);
        }
        if (!_stricmp(command, "identBufFile")) {
            char *bufFile, *bufMap;
            bufFile = strtok(NULL, " ");
            bufMap = strtok(NULL, " ");
            bufType = "smartFile";

            if (bufFile == NULL) {
                dprintf("[Byakugan] This command requires a path to an input file and map (CSV) from 010\n");
                return (S_OK);
            }

            //these settings are explicting for 010 CSV export
            const char field_terminator = ',';
            const char line_terminator  = '\n';
            const char enclosure_char   = '"';

            //create parse object
            csv_parser file_parser;

            /* Define how many records we're gonna skip. This could be used to skip the column definitions. */
            file_parser.set_skip_lines(1);

            /* Specify the file to parse */
            file_parser.init(bufMap);

            /* Here we tell the parser how to parse the file */
            file_parser.set_enclosed_char(enclosure_char, ENCLOSURE_OPTIONAL);

            file_parser.set_field_term_char(field_terminator);

            file_parser.set_line_term_char(line_terminator);

            /* Check to see if there are more records, then grab each row one at a time */
            while(file_parser.has_more_rows())
            {
                csv_row fileRecord = file_parser.get_row();

                //the miracle of STL hex string conversion :)           
                istringstream stFileOffset(fileRecord[2].c_str());
                istringstream stOffSetSize(fileRecord[3].c_str());
                unsigned int offset;
                unsigned int size;
                stFileOffset >> hex >> offset;
                stOffSetSize >> hex >> size;

                //dprintf("Allocating Buffer Name:%s at offset: %d with size: %d\n", fileRecord[0].c_str(), offset, size);

                //create individual buffers with the record type as a name and using the offset and size
                identBufJutsu(bufType, (char *)fileRecord[0].c_str(), bufFile, size, offset);
            }
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
	char    *command, *heapName, *logName;
	PVOID	heapHandle;
	
	INIT_API();
    
    command = strtok((char *)args, " ");
	
	if (command == NULL) {
		tenkHelp();
		return (S_OK);
	}
	else if (!_stricmp(command, "model")) {
    	if(hookRtlHeap(1, NULL)) {
        	dprintf("[Byakugan] Unable to begin realtime heap modeling.\n");
            EXIT_API();
        	return (S_FALSE);
    	}
	}
	else if (!_stricmp(command, "log")) {
		logName = strtok(NULL, " ");
		if (logName == NULL) {
			dprintf("[Byakugan] Please provide a log name.\n");
			return (S_FALSE);
		}
    	if(hookRtlHeap(2, logName)) {
			dprintf("[Byakugan] Unable to begin realtime heap modeling.\n");
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
