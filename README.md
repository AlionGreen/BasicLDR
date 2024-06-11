# Description
BasicLDR is a tool designed to download a PNG from a specified URL into memory, extract and decrypt an embedded DLL from the last IDAT section of PNG, and execute it using Reflective DLL Injection technique. 

Reflective DLL Injection, first introduced by Stephen Fewer, is a well-known technique for loading DLLs from memory. This project does not introduce any new techniques. Its primary purpose is for educational learning, allowing me to gain a deeper understanding of Reflective DLL Injection and other malware techniques by reimplementing them from scratch. Additionally, it provides a foundation for developing a custom loader builder with various evasive techniques in the future. 

I have utilized content and projects from other researchers, as mentioned in the credit section, to understand and implement this project.

This project is intended for educational purposes only.

### Features 
- Used Native API for most of the functions in the project. But it's not the case for all of them. 
- Used Dynamic API name hashing. 
- Used Custom `GetModuleHandle` and `GetProcAddress` functinos. 
- Used stack strings as a basic way to hide strings. 
- Utilizing PNG IDAT sections for embedding the DLL.

## ReflectiveDLLLoader
- Downloads a PNG from the specified URL into memory (the URL is specified in the main function).
- Finds and extracts the last IDAT section of the PNG, which contains an encrypted DLL.
- Decrypts the DLL using SystemFunction033. 
- Maps the DLL headers and sections into memory and executes it (Reflective DLL Injection).

### Usage
- **Encrypt the DLL**: Use `DLLCryptor` to encrypt your DLL with a key. TestDLL can be used for testing purposes.
- **Append Encrypted DLL to PNG**: Use `png_tool.py` to embed the encrypted DLL into a PNG file.
- **Host the PNG**: Host the PNG file on a web server.
	- **Note**: To avoid dropping the PNG on disk, serve it with the appropriate `Content-Type`.
- **Configure the URL**: Specify the URL of the hosted PNG in the `ReflectiveDLLLoader` code and build the project.
	- **Note**: Ensure the project is built in x64 mode.
- **Run the Loader**: Execute the `ReflectiveDLLLoader` project.

## DLLCrypter
- Use this tool to encrypt the DLL using.   

## TestDLL
- Used for testing the loader. 

## png_tool.py
- This tool creates a new IDAT section in the PNG and embeds the binary file content inside it.

# Todo list
- [ ] ToDo: Create a builder application to choose between various options for building the loader (specifying custom export functions, etc.).
- [ ] ToDo: Implement a key server to dynamically receive the decryption key.
- [ ] ToDo: Bypass Image Load Kernel Callbacks for additional loaded modules.
- [ ] ToDo: Implement different methods for executing the code (currently, it only runs with the main thread).

# Credit
- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Sektor7 Malware Development Intermediate](https://institute.sektor7.net/rto-maldev-intermediate)
- [blog.malicious.group](https://blog.malicious.group/writing-your-own-rdi-srdi-loader-using-c-and-asm/)
- [DarkLoadLibrary](https://github.com/bats3c/DarkLoadLibrary)
- [osandamalith.com](https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/)
- [Stardust](https://github.com/Cracked5pider/Stardust/tree/main)
- ChatGPT

