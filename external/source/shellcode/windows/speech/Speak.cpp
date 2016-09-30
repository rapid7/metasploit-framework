#include <Objbase.h>
#include <sapi.h>

int wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] ) {
    ISpVoice * pVoice = NULL;
    DWORD iid_ispvoice[] = {0x6c44df74, 0x499272b9, 0x99efeca1, 0xd422046e};
    DWORD clsid_spvoice[] = {0x96749377, 0x11d23391, 0xc000e39e, 0x9673794f};
    DWORD clsctx_all = 0x17;

    ::CoInitialize(NULL);

    CoCreateInstance((REFCLSID)clsid_spvoice, NULL, clsctx_all, (REFIID)iid_ispvoice, (void **)&pVoice);
    pVoice->Speak(argv[1], 0, NULL);
    return TRUE;
}
