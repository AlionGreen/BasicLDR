// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif

/*****************************************************************************
Definition of the TLS Callback functions to execute.
/*****************************************************************************/
void	tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext);
void	tls_callback2(PVOID hModule, DWORD dwReason, PVOID pContext);

/*****************************************************************************
CRT allows the program to register TLS Callbacks.
The Callbacks to execute are found in a NULL terminated Array.

A cariable of type PIMAGE_TLS_CALLBACK pointing to the callback must be
declared in the CRT to register it in this array.

The compiler can concatenate into one section using the $ symbol.

The CRT section makes use of a specific naming convention; .CRT$XLx where x
can be anything between A-Z. A is the beinning, Z is the null terminator.
All XLx are concatenated into the .CRT section.

Concatenation is done alphabetically, so the callback in .CRT$XLB will be
called before .CRT$XLC.
******************************************************************************/


/*****************************************************************************
Decalre first CRT, containing only one callback pointer.

Note: under x64 it must be a const_seg, for x86 it must be a data_seg.
******************************************************************************/
#ifdef _WIN64
#pragma const_seg(".CRT$XLB")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLB")
EXTERN_C
#endif

// The name of the variable & function bellow can be whatever you want. It's 
// the section name it belongs to (above) and the variable type that is
// important.
// Note: it is declared with EXTERN_C to avoid name wrangling of CPP.
PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)tls_callback1;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64 End section decleration


/*****************************************************************************
Declare second CRT, containing, again, only one callback pointer.
******************************************************************************/
#ifdef _WIN64
#pragma const_seg(".CRT$XLC")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLC")
EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func2 = (PIMAGE_TLS_CALLBACK)tls_callback2;

#ifdef _WIN64
#pragma const_seg()
#else
#pragma code_seg()
#endif //_WIN64 End section decleration


/*****************************************************************************
First TLS Callback
Set above to segment CRT$XLB
******************************************************************************/
void	tls_callback1(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH) {
		// This will be loaded in each DLL thread attach
		MessageBox(0, L"TLS Callback 1: Thread Attach Triggered", L"TLS", 0);
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, L"TLS Callback: Process Attach Triggered", L"TLS", 0);
	}
}


/*****************************************************************************
Second TLS Callback
Set above to segment CRT$XLC
******************************************************************************/
void	tls_callback2(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH) {
		// This will be loaded in each DLL thread attach
		MessageBox(0, L"TLS Callback 2: Thread Attach Triggered", L"TLS_Thread", 0);
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		MessageBox(0, L"TLS Callback 1: Process Attach Triggered", L"TLS_Process", 0);
	}
}



extern "C" __declspec(dllexport) void Myfunc() {

	MessageBoxA(0, "Hello World!", "what?", 0);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Myfunc();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

