#include "stdafx.h"
#include "console.h"
#include "memory.h"
#include "VEHHook.h"

DWORD CALLBACK cbEjectDLL(LPVOID hModule)
{
	Sleep(100);
	FreeLibraryAndExitThread((HMODULE)hModule, 0);
	return 0;
}

signed int stackOffset;
void cbHwidCall(const CHook* pHook, PCONTEXT pContextRecord)
{
	printf("OH GOD, HWID WAS JUST CALLED\n");
	char** pHwidString = (char**)(pContextRecord->Ebp + stackOffset);
	printf("[ebp-%xh] = %s", -stackOffset, *pHwidString);
	*pHwidString = new char[2000];
	strcpy(*pHwidString, R"(<SystemFingerprint VideoCardId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" NetworkCardId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" NetworkGatewayId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" HardriveId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" ComputerName="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="><NetworkAdapters IsList="1"><NetworkAdapter Id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/><NetworkAdapter Id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/><NetworkAdapter Id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/><NetworkAdapter Id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/></NetworkAdapters><HardDrives IsList="1"><HardDrive UniqueId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" ModelId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" RevisionId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" VendorId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" SizeId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/><HardDrive UniqueId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" ModelId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" RevisionId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" VendorId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" SizeId="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="/></HardDrives></SystemFingerprint>)");
	while (!GetAsyncKeyState(VK_F7)) // spinlock
		Sleep(50);
}

void Init()
{
	printf("wowow im in ps2 launchpad!!\n");
	DWORD sigLocation = FindPattern((DWORD)GetModuleHandle(NULL) + 0x10000, 0x10000, "\x33\xFF\xC7\x85\x00\x00\xFF\xFF\x00\x00\x00\x00\x89\xBD\x00\x00\xFF\xFF\x89\xBD\x00\x00\xFF\xFF\xC7\x85\x00\x00\xFF\xFF\x00\x00\x00\x00\x8D\x8D\x00\x00\xFF\xFF\x51\x57\x89\x7D\x00\xE8", "3FC8??FF????8B??FF8B??FFC8??FF????88??FF5587?E");
	DWORD hookTarget = sigLocation + 0x32;
	printf("hooktarget=%x\n", hookTarget);
	stackOffset = *(PDWORD)(sigLocation + 4);
	printf("stack offset = %d\n", stackOffset);

	InitHook();
	SetHLTHook(hookTarget, (HltProc)cbHwidCall, 0x6);
	printf("hwid call has been hooked; it's safe to resume the process now\n");
}

DWORD CALLBACK cbThreadStart(LPVOID hModule)
{
	Beep(440, 250);
	CreateConsole();
	ClearConsole();

	Init();

	while (!GetAsyncKeyState(VK_F6))
		Sleep(10);
	ShutdownHook();
	Beep(440, 250);

	CreateThread(NULL, 0, cbEjectDLL, hModule, NULL, NULL);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, cbThreadStart, hModule, NULL, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
