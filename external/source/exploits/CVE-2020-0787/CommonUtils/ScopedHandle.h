#pragma once
class ScopedHandle
{
	HANDLE g_h;

public:
	ScopedHandle(HANDLE h, bool duplicate);
	void Close();
	void Reset(HANDLE h);
	bool IsValid() const {
		return (g_h != nullptr) && (g_h != INVALID_HANDLE_VALUE);
	}
	ScopedHandle(const ScopedHandle& other);
	ScopedHandle& operator=(const ScopedHandle& other);

	ScopedHandle(ScopedHandle&& other);	
	ScopedHandle& operator=(ScopedHandle&& other);

	operator HANDLE() const {
		return g_h;
	}	

	~ScopedHandle();
};

