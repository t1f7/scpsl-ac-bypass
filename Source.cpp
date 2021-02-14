#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32W modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32FirstW(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32NextW(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

uintptr_t GetProcAddressEx(HANDLE hProcess, DWORD pid, const wchar_t* module, const char* function)
{
	if (!module || !function || !pid || !hProcess)
		return 0;

	uintptr_t moduleBase = GetModuleBaseAddress(pid, module);

	if (!moduleBase)
		return 0;

	IMAGE_DOS_HEADER Image_Dos_Header = { 0 };

	if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase), &Image_Dos_Header, sizeof(IMAGE_DOS_HEADER), nullptr))
		return 0;

	if (Image_Dos_Header.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	IMAGE_NT_HEADERS Image_Nt_Headers = { 0 };

	if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + Image_Dos_Header.e_lfanew), &Image_Nt_Headers, sizeof(IMAGE_NT_HEADERS), nullptr))
		return 0;

	if (Image_Nt_Headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_EXPORT_DIRECTORY Image_Export_Directory = { 0 };
	uintptr_t img_exp_dir_rva = 0;

	if (!(img_exp_dir_rva = Image_Nt_Headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
		return 0;

	if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + img_exp_dir_rva), &Image_Export_Directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
		return 0;

	uintptr_t EAT = moduleBase + Image_Export_Directory.AddressOfFunctions;
	uintptr_t ENT = moduleBase + Image_Export_Directory.AddressOfNames;
	uintptr_t EOT = moduleBase + Image_Export_Directory.AddressOfNameOrdinals;

	WORD ordinal = 0;
	SIZE_T len_buf = strlen(function) + 1;
	char* temp_buf = new char[len_buf];

	for (size_t i = 0; i < Image_Export_Directory.NumberOfNames; i++)
	{
		uintptr_t tempRvaString = 0;

		if (!ReadProcessMemory(hProcess, (LPCVOID)(ENT + (i * sizeof(uintptr_t))), &tempRvaString, sizeof(uintptr_t), nullptr))
			return 0;

		if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + tempRvaString), temp_buf, len_buf, nullptr))
			return 0;

		if (!lstrcmpi(function, temp_buf))
		{
			if (!ReadProcessMemory(hProcess, (LPCVOID)(EOT + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr))
				return 0;

			uintptr_t temp_rva_func = 0;

			if (!ReadProcessMemory(hProcess, (LPCVOID)(EAT + (ordinal * sizeof(uintptr_t))), &temp_rva_func, sizeof(uintptr_t), nullptr))
				return 0;

			delete[] temp_buf;
			return moduleBase + temp_rva_func;
		}
	}
	delete[] temp_buf;
	return 0;
}


int main()
{
	//debug
	const char* procName = "SCPSL.exe";
	auto procWName = L"SCPSL.exe";

	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(procName, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		DWORD Err = GetLastError();
		char buf[500];
		sprintf_s<500>(buf, "OpenProcess failed : 0x%X(id: %i)\n", Err, PID);
		MessageBox(NULL, buf, "error", 0);
		system("PAUSE");
		return 0;
	}

	// find all threads
	auto external_base = GetModuleBaseAddress(PID, procWName);
	bool acDisabled = false;

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		char buf[500];
		sprintf_s<500>(buf, "Access to SCPSL failed : 0x%X(id: %i)\n", Err, PID);
		MessageBox(NULL, buf, "error", 0);
		system("PAUSE");
		return 0;
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	if (Thread32First(h, &te)) {
		do {
			if (te.th32OwnerProcessID != PID) continue;

			if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
				sizeof(te.th32OwnerProcessID)) {

				DWORD64 baseAddress = 0;
				auto handle = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (!handle) {
					printf("cant open thread :( \n");
				}
				else {
					acDisabled = true;
					TerminateThread(handle, 0);
					CloseHandle(handle);
					break;
				}
			}
			te.dwSize = sizeof(te);
		} while (Thread32Next(h, &te));
	}
	CloseHandle(h);

	CloseHandle(hProc);

	if (acDisabled) printf("AC disabled!\n");
	else printf("AC was not disabled ???\n");

	Sleep(500);

	return 0;
}