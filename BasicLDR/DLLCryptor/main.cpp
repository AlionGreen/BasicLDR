#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring *memoryRegion,
	struct ustring *keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

int main(int argc, char *argv[]) {
	printf("[*] RC4 Shellcode Encrypter using Systemfunction032/033\n");

	if (argc != 4) {
		printf("Usage: %s <path to binary file> <encryption key> <output file name>\n", argv[0]);
		return 1;
	}

	const char* filePath = argv[1];
	const char* encryptionKey = argv[2];
	const char* outputFileName = argv[3];

	FILE *file;
	errno_t err = fopen_s(&file, filePath, "rb");
	if (err != 0 || file == NULL) {
		perror("Failed to open file");
		return 1;
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	// Allocate memory for shellcode
	unsigned char *shellcode = (unsigned char *)malloc(fileSize);
	if (!shellcode) {
		perror("Memory allocation failed");
		fclose(file);
		return 1;
	}

	// Read shellcode from file
	fread(shellcode, 1, fileSize, file);
	fclose(file);

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");

	key.Buffer = (PUCHAR)encryptionKey;
	key.Length = strlen(encryptionKey); // excluding null terminator
	key.MaximumLength = key.Length;

	_data.Buffer = shellcode;
	_data.Length = fileSize;
	_data.MaximumLength = fileSize;

	SystemFunction033(&_data, &key);

	// Writing the encrypted shellcode to a binary file
	FILE *outfile;
	err = fopen_s(&outfile, outputFileName, "wb");
	if (err != 0 || outfile == NULL) {
		perror("Failed to open output file");
		free(shellcode);
		return 1;
	}

	fwrite(_data.Buffer, 1, _data.Length, outfile);
	fclose(outfile);

	printf("Encrypted shellcode has been written to %s\n", outputFileName);

	free(shellcode);
	return 0;
}

