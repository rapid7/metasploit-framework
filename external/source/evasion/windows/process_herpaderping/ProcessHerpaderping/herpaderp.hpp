#pragma once

namespace Herpaderp
{
    constexpr static char _TargetFileName[FILE_MAX_PATH] = { 'T', 'A', 'R', 'G', 'E', 'T', 'F', 'I', 'L', 'E', 'N', 'A', 'M', 'E' };
    constexpr static char _ReplaceWithFileName[FILE_MAX_PATH] = { 'R', 'E', 'P', 'L', 'A', 'C', 'E', 'F', 'I', 'L', 'E', 'N', 'A', 'M', 'E' };

// If the Herpaderping loader file is changed, update the following sizes accordingly
// It should match the loader sizes (ProcessHerpaderpingTemplate_x64.exe and ProcessHerpaderpingTemplate_x86.exe)
#ifdef _WIN64
#define PAYLOAD_PE_SIZE 0x3400
#else
#define PAYLOAD_PE_SIZE 0x3200
#endif

    static unsigned char payload[PAYLOAD_PE_SIZE] = "PAYLOAD";

    constexpr static uint32_t RandPatternLen{ 0x200 };

    _Must_inspect_result_ HRESULT ExecuteProcess();
}
