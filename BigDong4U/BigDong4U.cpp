#include "stdafx.h"

DWORD GetEntryPoint(LPWSTR szPath)
{
	BY_HANDLE_FILE_INFORMATION bhfi;
	HANDLE hMapping;
	char *lpBase;
	HANDLE hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;

	if (!GetFileInformationByHandle(hFile, &bhfi))
		return NULL;

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, bhfi.nFileSizeHigh, bhfi.nFileSizeLow, NULL);
	if (!hMapping)
		return NULL;
	lpBase = (char *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, bhfi.nFileSizeLow);
	if (!lpBase)
		return NULL;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(lpBase + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	DWORD dwEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;

	UnmapViewOfFile((LPCVOID)lpBase);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return dwEntryPoint;
}

HANDLE hProcess;
int fail(char* fmt, ...)
{
	printf("error: ");
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	_getwche();	

	TerminateProcess(hProcess, -1);
	CloseHandle(hProcess);
	return 1;
}

int main()
{
	printf("Big planetside hwid hak by ecx\n\n");

	LPWSTR szPathPs2 = L"E:\\Programs\\SteamApps\\steamapps\\common\\PlanetSide 2\\";
	WCHAR szPathExe[MAX_PATH];
	wcscpy_s(szPathExe, szPathPs2);
	wcscat_s(szPathExe, L"LaunchPad.exe");

	printf("workdir=%ls, pe path=%ls\n", szPathPs2, szPathExe);

	PROCESS_INFORMATION procInfo;
	STARTUPINFO startupInfo = { 0 };
	if (!CreateProcess(szPathExe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, szPathPs2, &startupInfo, &procInfo))
		return fail("CreateProcess failed: %d\n", GetLastError());

	hProcess = procInfo.hProcess;
	HANDLE hThread = procInfo.hThread;

	CONTEXT context;
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(hThread, &context);
	DWORD dwBaseAddr = 0;
	ReadProcessMemory(hProcess, (PVOID)(context.Ebx + 8), &dwBaseAddr, sizeof(DWORD), NULL);
	printf("peb=%x, base address=%x\n", context.Ebx, dwBaseAddr);

	LPVOID pEntryPoint = (LPVOID)(GetEntryPoint(szPathExe) + dwBaseAddr);
	if (!pEntryPoint)
		return fail("Failed to find entrypoint\n");
	printf("entrypoint = %p\n", pEntryPoint);

	DWORD dwPrevProtect;
	VirtualProtectEx(hProcess, pEntryPoint, 2, PAGE_EXECUTE_READWRITE, &dwPrevProtect);
	BYTE oepBytes[2];
	ReadProcessMemory(hProcess, pEntryPoint, oepBytes, 2, NULL);
	WriteProcessMemory(hProcess, pEntryPoint, "\xEB\xFE", 2, NULL);
	
	ResumeThread(hThread);
	
	for (int i = 0; context.Eip != (DWORD)pEntryPoint; Sleep(100))
	{
		if (++i > 50)
		{
			TerminateProcess(procInfo.hProcess, -1);
			return fail("entrypoint trap trimed out after 5s\n");
		}
		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);
	}
	printf("entrypoint trap hit, injecting the dll now!\n");

	LPCSTR szPath = R"(E:\documents\visual studio 2015\Projects\BigDong4U\Release\BigDong4Ps2.dll)";
	int len = strlen(szPath);
	LPVOID pBuf = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, pBuf, szPath, len, NULL);
	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"), pBuf, NULL, NULL);

	printf("Dll injected, press any key to resume the process\n");
	_getwche();

	WriteProcessMemory(hProcess, pEntryPoint, oepBytes, 2, NULL);
	ResumeThread(hThread);

	CloseHandle(hProcess);
	CloseHandle(hThread);

	printf("success! press any key to exit\n");

	_getwche();
    return 0;
}
