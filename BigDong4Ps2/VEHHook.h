#pragma once

class CHook;

typedef void(*HltProc)(const CHook*, PCONTEXT);

class CHook
{
public:
	DWORD dwAddress;
	DWORD dwHookReturnAddr;
	HltProc cbHook;

	BYTE* pbOverwritten;
	size_t nOverwritten;

	CHook(DWORD dwAddress, HltProc cbHook, size_t size);
	~CHook();

	bool OverwriteCode() const;
	bool ResetCode() const;
};

bool InitHook();

bool ShutdownHook();

CHook* SetHLTHook(DWORD dwAddress, HltProc cbHook, size_t size);

bool RemoveHLTHook(DWORD dwAddress);
