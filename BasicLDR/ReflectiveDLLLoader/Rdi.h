#pragma once

#include <vector>
#include <Windows.h>
#include "utils.h"
#include "PebUtils.h"


typedef struct _BASE_RELOCATION_ENTRY { 
	WORD Offset : 12; 
	WORD Type : 4; } BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY; 

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;


typedef struct _DLLMODULE {
	PCHAR					dll_bytes;
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	SIZE_T					dll_image_size;
	PVOID					dll_base;
} DLLMODULE, *PDLLMODULE;


#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
#define FILL_STRING(string, buffer) \
	string.Length = (USHORT)strlen(buffer);   \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

int ReflectiveDLLInjection(std::vector<char> *dllBuffer);


typedef BOOL(__stdcall *DLLEntry)(HINSTANCE dll, DWORD reason, LPVOID reserved);
typedef VOID(__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
typedef NTSTATUS(__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(__stdcall *LdrLoadDll_t)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef NTSTATUS(__stdcall *RtlMultiByteToUnicodeN_t)(PWCH MultiByteString, ULONG MaxBytesInMultiByteString, PULONG BytesInMultiByteString, PCSTR UnicodeString, ULONG BytesInUnicodeString);
typedef NTSTATUS(__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG NumberOfBytesToFlush);
typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
