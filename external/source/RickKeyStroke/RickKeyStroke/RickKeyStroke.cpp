// RickKeyStroke.cpp
//

#include "stdafx.h"
#include <windows.h>
#include <string>
#include <stdio.h>

using namespace std;

#define WM_MY_KEYDOWN (WM_USER + 1)

int lyricsCounter;

string lyrics = "We're no strangers to love\n" 
"You know the rules and so do I\n"
"A full commitment's what I'm thinking of\n"
"You wouldn't get this from any other guy\n"
"I just wanna tell you how I'm feeling\n"
"Gotta make you understand\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n"
"We've known each other for so long\n"
"Your heart's been aching but\n"
"You're too shy to say it\n"
"Inside we both know what's been going on\n"
"We know the game and we're gonna play it\n"
"And if you ask me how I'm feeling\n"
"Don't tell me you're too blind to see\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n"
"Ooh give you up\n"
"Ooh give you up\n"
"Ooh\n"
"Never gonna give never gonna give\n"
"Give you up\n"
"Ooh\n"
"Never gonna give never gonna give\n"
"Give you up\n"
"We've know each other for so long\n"
"Your heart's been aching but\n"
"You're too shy to say it\n"
"Inside we both know what's been going on\n"
"We know the game and we're gonna play it\n"
"I just wanna tell you how I'm feeling\n"
"Gotta make you understand\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n"
"Never gonna give you up\n"
"Never gonna let you down\n"
"Never gonna run around and desert you\n"
"Never gonna make you cry\n"
"Never gonna say goodbye\n"
"Never gonna tell a lie and hurt you\n";

HHOOK hKeyHook;


LRESULT WINAPI KeyEvent(int nCode, WPARAM wParam, LPARAM lParam)
{
	KBDLLHOOKSTRUCT*  kbd = (KBDLLHOOKSTRUCT*)lParam;
	BOOL fEatKeystroke = FALSE;
	
	if (nCode < 0 || (kbd->flags & 0x10)) {
		return CallNextHookEx(hKeyHook, nCode, wParam, lParam);
	}

	if( (nCode == HC_ACTION) && ((wParam == WM_SYSKEYDOWN) || (wParam == WM_KEYDOWN)) )
	{
		INPUT aiKeyDownUp[2];
		WORD wScanCode	= MapVirtualKey( (UCHAR) VkKeyScan(lyrics[lyricsCounter]), MAPVK_VK_TO_VSC);

		ZeroMemory(aiKeyDownUp, sizeof(aiKeyDownUp));
		for (int i=0; i<2; i++)
		{
			aiKeyDownUp[i].type = INPUT_KEYBOARD;
			aiKeyDownUp[i].ki.wVk = (UCHAR) VkKeyScan(lyrics[lyricsCounter]);
			aiKeyDownUp[i].ki.wScan = wScanCode;
			aiKeyDownUp[i].ki.dwFlags = i==1 ? 0 : KEYEVENTF_KEYUP | KEYEVENTF_UNICODE;
			aiKeyDownUp[i].ki.time = 0;
			aiKeyDownUp[i].ki.dwExtraInfo = 0;
		}
		SendInput(2, aiKeyDownUp, sizeof(INPUT));

		if(lyricsCounter < lyrics.size() - 1)
		{
			lyricsCounter++;
		}
		else
		{
			lyricsCounter = 0;
		}

		return 1;
	}

	return CallNextHookEx(hKeyHook, nCode, wParam, lParam);
}

//int _tmain(int argc, _TCHAR* argv[])
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	hKeyHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)KeyEvent, GetModuleHandle(NULL), 0);
	lyricsCounter = 0;
 
	MSG message;
	while(GetMessage(&message, NULL, 0, 0))
	{
	TranslateMessage(&message);
	DispatchMessage(&message);
	}
 
	UnhookWindowsHookEx(hKeyHook);

	return 0;
}