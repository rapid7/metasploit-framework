#pragma once
#include <comdef.h>

class FileSymlink
{	
	bstr_t m_junctiondir;
	bstr_t m_linkname;
	bstr_t m_target;
	bool m_created_junction;
	HANDLE m_hlink;	
	bool m_permanent;

public:
	FileSymlink(bool permanent);
	FileSymlink();
	FileSymlink(FileSymlink&& other);
	FileSymlink& operator=(FileSymlink&& other);
	FileSymlink(const FileSymlink& other) = delete;
	FileSymlink& operator=(const FileSymlink& other) = delete;

	bool CreateSymlink(LPCWSTR symlink, LPCWSTR target, LPCWSTR baseobjdir);
	bool ChangeSymlink(LPCWSTR newtarget);	

	~FileSymlink();
};

