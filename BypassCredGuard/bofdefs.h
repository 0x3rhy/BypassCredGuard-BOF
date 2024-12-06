#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "beacon.h"

	void go(char* args, int len);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OPEN 0x00000001

	typedef struct _LargePointer { BYTE data[16]; } LargePointer;
	typedef struct _TOKEN_PRIVILEGES_STRUCT { DWORD PrivilegeCount; LUID Luid; DWORD Attributes; } TOKEN_PRIVILEGES_STRUCT, * PTOKEN_PRIVILEGES_STRUCT;
	typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
	typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
	typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
	typedef enum _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;

	WINBASEAPI NTSTATUS WINAPI NTDLL$NtOpenProcessToken(HANDLE, DWORD, PHANDLE);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtAdjustPrivilegesToken(HANDLE, BOOL, PTOKEN_PRIVILEGES_STRUCT, DWORD, PVOID, PVOID);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtGetNextProcess(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtClose(HANDLE);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtTerminateProcess(HANDLE ProcessHandle, int ExitStatus);
	WINBASEAPI NTSTATUS WINAPI NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

	WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
	WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
	WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
	WINBASEAPI  void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
	WINBASEAPI void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
	WINBASEAPI void* __cdecl MSVCRT$malloc(size_t _Size);
	WINBASEAPI void* __cdecl MSVCRT$calloc(size_t number, size_t size);
	WINBASEAPI void __cdecl MSVCRT$free(void* _Memory);
	WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t* _Str);
	WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
	WINBASEAPI BOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
	WINBASEAPI BOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
	WINBASEAPI VOID WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
	WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
	WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
	WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
	WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
	WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
	WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
	WINBASEAPI DWORD WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
	WINBASEAPI DWORD WINAPI KERNEL32$SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
	WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
	WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
	WINBASEAPI BOOL WINAPI KERNEL32$DebugActiveProcessStop(DWORD dwProcessId);

#ifdef __cplusplus
}
#endif

#define NtOpenProcessToken NTDLL$NtOpenProcessToken
#define NtAdjustPrivilegesToken NTDLL$NtAdjustPrivilegesToken
#define NtGetNextProcess NTDLL$NtGetNextProcess
#define NtQueryInformationProcess NTDLL$NtQueryInformationProcess
#define NtReadVirtualMemory NTDLL$NtReadVirtualMemory
#define NtClose NTDLL$NtClose
#define NtCreateFile NTDLL$NtCreateFile
#define NtReadFile NTDLL$NtReadFile
#define NtWriteVirtualMemory NTDLL$NtWriteVirtualMemory
#define NtTerminateProcess NTDLL$NtTerminateProcess
#define NtProtectVirtualMemory NTDLL$NtProtectVirtualMemory

#define OpenProcess KERNEL32$OpenProcess
#define CloseHandle KERNEL32$CloseHandle
#define CreateProcessA KERNEL32$CreateProcessA
#define memcpy MSVCRT$memcpy
#define memset MSVCRT$memset
#define malloc MSVCRT$malloc
#define calloc MSVCRT$calloc
#define free MSVCRT$free
#define wcslen MSVCRT$wcslen
#define vsnprintf MSVCRT$vsnprintf
#define InitializeProcThreadAttributeList KERNEL32$InitializeProcThreadAttributeList
#define UpdateProcThreadAttribute KERNEL32$UpdateProcThreadAttribute
#define DeleteProcThreadAttributeList KERNEL32$DeleteProcThreadAttributeList
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define VirtualAllocEx KERNEL32$VirtualAllocEx
#define VirtualProtectEx KERNEL32$VirtualProtectEx
#define WriteProcessMemory KERNEL32$WriteProcessMemory
#define QueueUserAPC KERNEL32$QueueUserAPC
#define ResumeThread KERNEL32$ResumeThread
#define GetThreadContext KERNEL32$GetThreadContext
#define SetThreadContext KERNEL32$SetThreadContext
#define GetLastError KERNEL32$GetLastError
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define DebugActiveProcessStop KERNEL32$DebugActiveProcessStop

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

#ifdef BOF
#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)
#else
#define intZeroMemory(addr,size) memset((addr),0,size)
#endif
