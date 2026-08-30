#pragma once

#include <string>
#include <vector>

class ReparsePoint
{	
public:

	static bool CreateMountPoint(const std::wstring& path, const std::wstring& target, const std::wstring& printname);
	static bool DeleteMountPoint(const std::wstring& path);
	static std::wstring GetMountPointTarget(const std::wstring& path);
	static bool CreateRawMountPoint(const std::wstring& path, DWORD reparse_tag, const std::vector<BYTE>& buffer);
	static bool IsMountPoint(const std::wstring& path);
	static bool IsSymlink(const std::wstring& path);
	static bool ReadMountPoint(const std::wstring& path, std::wstring& target, std::wstring& printname);
	static bool ReadSymlink(const std::wstring& path, std::wstring& target, std::wstring& printname, unsigned int* flags);
	static bool ReadRaw(const std::wstring& path, unsigned int* reparse_tag, std::vector<BYTE>& raw_data);
	static bool IsReparsePoint(const std::wstring& path);
	static bool CreateSymlink(const std::wstring& path, const std::wstring& target, const std::wstring& printname, bool relative);
	static bool CreateSymlink(HANDLE h, const std::wstring& target, const std::wstring& printname, bool relative);

	static int GetLastError();
};

