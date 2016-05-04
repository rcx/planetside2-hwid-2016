#include "stdafx.h"
#include "VEHHook.h"

#include <unordered_map>

CHook::CHook(DWORD dwAddress, HltProc cbHook, size_t size)
{
	this->dwAddress = dwAddress;
	this->cbHook = cbHook;
	this->dwHookReturnAddr = this->dwAddress + size;

	this->nOverwritten = size;
	this->pbOverwritten = new BYTE[size + 6];
	
	// TODO: this method doesn't support hooking at instructions that are relative
	memcpy(this->pbOverwritten, (void*) dwAddress, size); // Copy old bytes
	// Assemble a far indirect JMP to the rest of the code
	this->pbOverwritten[size] = 0xFF;
	this->pbOverwritten[size + 1] = 0x25;
	*(DWORD*)(&this->pbOverwritten[size + 2]) = (DWORD)&this->dwHookReturnAddr;

	DWORD dwPrevProtect;
	VirtualProtect(this->pbOverwritten, size, PAGE_EXECUTE_READWRITE, &dwPrevProtect);
}

CHook::~CHook()
{
	delete[] this->pbOverwritten;
}

bool CHook::OverwriteCode() const
{
	DWORD dwOldProtect;
	if (!VirtualProtect((LPVOID)dwAddress, nOverwritten, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;
	memset((void*)dwAddress, 0x90, nOverwritten); // NOP instructions
	*(PBYTE)dwAddress = 0xF4; // HLT
	if (!VirtualProtect((LPVOID)dwAddress, nOverwritten, dwOldProtect, &dwOldProtect))
		return false;
	return true;
}

bool CHook::ResetCode() const
{
	DWORD dwOldProtect;
	if (!VirtualProtect((LPVOID)dwAddress, nOverwritten, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return false;
	memcpy((void*)dwAddress, pbOverwritten, nOverwritten);
	if (!VirtualProtect((LPVOID)dwAddress, nOverwritten, dwOldProtect, &dwOldProtect))
		return false;
	return true;
}

static std::unordered_map<DWORD, CHook*> hooks;
PVOID pHandler;

const CHook* pCurHook;
PCONTEXT pContext;
DWORD dwJmpTarget;

void __declspec(naked) cbHlt()
{
	__asm
	{
		pushad // Preserve registers and flags
		pushfd
		push ebp // Function prologue
		mov ebp, esp
	}

	pCurHook->cbHook(pCurHook, pContext);

	_asm
	{
		mov esp, ebp // Function epilogue
		pop ebp

		popfd // Restore registers and flags
		popad
		jmp dwJmpTarget // Jump to buffer containing overwritten code and a jump back to where eip would be
	}
}

LONG CALLBACK ExceptionFilter(EXCEPTION_POINTERS* pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		DWORD eip = pExceptionInfo->ContextRecord->Eip;
		if (hooks.find(eip) != hooks.end())
		{
			pCurHook = hooks[eip];
			pContext = pExceptionInfo->ContextRecord;
			dwJmpTarget = (DWORD) pCurHook->pbOverwritten;

			pExceptionInfo->ContextRecord->Eip = (DWORD)cbHlt;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

bool InitHook()
{
	pHandler = AddVectoredExceptionHandler(true, ExceptionFilter);
	return pHandler != NULL;
}

bool ShutdownHook()
{
	while (!hooks.empty()) // No increment because of erase
		RemoveHLTHook(hooks.begin()->first);
	return RemoveVectoredExceptionHandler(pHandler) != 0;
}

CHook* SetHLTHook(DWORD dwAddress, HltProc cbHook, size_t size)
{
	hooks[dwAddress] = new CHook(dwAddress, cbHook, size);
	hooks[dwAddress]->OverwriteCode();
	return hooks[dwAddress];
}

bool RemoveHLTHook(DWORD dwAddress)
{
	CHook* hook = hooks[dwAddress];
	hooks.erase(dwAddress);
	bool bReturn = hook->ResetCode();
	delete hook;
	return bReturn;
}