#include "PebUtils.h"



PVOID GetProcAddresshash(void *dll_address, DWORD function_hash) {
	void *base = dll_address;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pAddressOfFunctions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
	PDWORD pAddressOfNames = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
	PWORD pAddressOfNameOrdinals = (unsigned short *)(PDWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

	for (unsigned long i = 0; i < export_directory->NumberOfNames; i++) {
		PCHAR pFunctionName = (PCHAR)((DWORD_PTR)base + pAddressOfNames[i]);
		unsigned short pFunctionOrdinal = (unsigned short)pAddressOfNameOrdinals[i];
		unsigned long pFunctionAddress = (unsigned long)pAddressOfFunctions[pFunctionOrdinal];

		if (function_hash == HASH_STR(pFunctionName))
			return (void *)((DWORD_PTR)base + pFunctionAddress);
	}
	return NULL;
}


HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {
	#ifdef _M_IX86
		PEB *ProcEnvBlk = (PEB *)__readfsdword(0x30);
	#else
		PEB *ProcEnvBlk = (PEB *)__readgsqword(0x60);
	#endif
	
	// return base address of a calling module
	if (sModuleName == NULL)
		return (HMODULE)(ProcEnvBlk);

	PEB_LDR_DATA *ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY *ModuleList = NULL;

	ModuleList = &ldr->InMemoryOrderModuleList;
	LIST_ENTRY *pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *pListEntry = pStartListEntry;
		pListEntry != ModuleList;
		pListEntry = pListEntry->Flink) {

		LDR_MODULE *pEntry = (PLDR_MODULE)((PBYTE)pListEntry - sizeof(LIST_ENTRY));

		if (wcscmp((const wchar_t *)pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE)pEntry->BaseAddress;
	}

	return NULL;
}


FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char *sProcName) {
	char *pBaseAddress = (char *)hMod;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBaseAddress + pDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER *pOptionalHeader = &pNtHeaders->OptionalHeader;
	IMAGE_DATA_DIRECTORY *pExportDataDirectory = (IMAGE_DATA_DIRECTORY *)(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY *pExportDirectoryAddress = (IMAGE_EXPORT_DIRECTORY *)(pBaseAddress + pExportDataDirectory->VirtualAddress);

	DWORD *pAddressOfFunctions = (DWORD *)(pBaseAddress + pExportDirectoryAddress->AddressOfFunctions);
	DWORD *pAddressOfNames = (DWORD *)(pBaseAddress + pExportDirectoryAddress->AddressOfNames);
	WORD *pAddressOfOrdinals = (WORD *)(pBaseAddress + pExportDirectoryAddress->AddressOfNameOrdinals);


	void *pProcAddr = NULL;
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD)sProcName & 0xFFFF;
		DWORD Base = pExportDirectoryAddress->Base;

		//check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirectoryAddress->NumberOfFunctions)
			return NULL;

		pProcAddr = (FARPROC)(pBaseAddress + (DWORD_PTR)pAddressOfFunctions[ordinal - Base]);

	}
	else {
		for (DWORD i = 0; i < pExportDirectoryAddress->NumberOfNames; i++) {
			char *sTmpFuncName = (char *)pBaseAddress + (DWORD_PTR)pAddressOfNames[i];

			if (strcmp(sProcName, sTmpFuncName) == 0) {
				pProcAddr = (FARPROC)(pBaseAddress + (DWORD_PTR)pAddressOfFunctions[pAddressOfOrdinals[i]]);

				/* forwarded functions --> this doesn't work for unmaped image */
				// [x] ToDo: make it work for unmapped image. 
				/* https://github.com/Speedi13/Custom-GetProcAddress-and-GetModuleHandle-and-more/blob/master/CustomWinApi.cpp */
				if (pProcAddr > ((BYTE*)pExportDirectoryAddress) &&
					pProcAddr < ((BYTE*)pExportDirectoryAddress + pExportDataDirectory->Size)) {

					PCHAR forwardedString = (PCHAR)pProcAddr;
					DWORD forwardedStringLen = (DWORD)strlen(forwardedString) + 1;

					if (forwardedStringLen >= 256)
						continue;

					char szForwardedLibraryName[256];
					memcpy(szForwardedLibraryName, forwardedString, forwardedStringLen);
					PCHAR forwardedFunctionName = NULL;
					PCHAR forwardedFunctionOrdinal = NULL;

					for (DWORD s = 0; s < forwardedStringLen; s++)
					{
						if (szForwardedLibraryName[s] == '.')
						{
							szForwardedLibraryName[s] = NULL;
							forwardedFunctionName = &forwardedString[s + 1];
							break;
						}
					}
					PIC_STRING(dllExtension, ".dll");
					strcat_s(szForwardedLibraryName, sizeof(szForwardedLibraryName), dllExtension);
					WCHAR wForwardedModuleName[MAX_PATH];
					size_t numberOfConverted;
					mbstowcs_s(&numberOfConverted, wForwardedModuleName, (const char*)szForwardedLibraryName, (ULONGLONG)sizeof(szForwardedLibraryName));
					_wcslwr_s(wForwardedModuleName);
					void* hLoadedModule = hlpGetModuleHandle(wForwardedModuleName);
					// [ ] ToDo: check for forwarded by ordinals

					UNICODE_STRING uForwardedModule;
					uForwardedModule.Length = static_cast<USHORT>(wcslen(wForwardedModuleName) * sizeof(wchar_t));
					uForwardedModule.MaximumLength = MAX_PATH + sizeof(WCHAR); 
					uForwardedModule.Buffer = wForwardedModuleName;

					PUNICODE_STRING pUnicodeString = &uForwardedModule;

					PIC_WSTRING(NTDLL, L"ntdll.dll");
					void *pNtdll = hlpGetModuleHandle(NTDLL);


					PIC_STRING(LdrLoadDll, "LdrLoadDll");
					DWORD LdrLoadDll_HASH = HASH_STR((PCHAR)LdrLoadDll);
					typedef NTSTATUS(__stdcall *LdrLoadDll_t)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
					LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)GetProcAddresshash(pNtdll, LdrLoadDll_HASH);

					if (hLoadedModule == NULL) {
						if (pLdrLoadDll(NULL, NULL, &uForwardedModule, &hLoadedModule))
							return NULL;
					}

					return hlpGetProcAddress((HMODULE)hLoadedModule, forwardedFunctionName);

				}

				break;
			}
		}
	}

	return (FARPROC)pProcAddr;
}