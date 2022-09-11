#pragma once
#include "../syscall.h"
#include <cstdint>

class winapi
{
public:
	winapi();
	~winapi();

	bool  ps_win32_close_handle(HANDLE Handle);
	
	// todo: add handle variant
	void* ps_win32_allocate_memory(void* BaseAddress, size_t Size, uint32_t AllocType, uint32_t Protect);

	bool  ps_win32_protect_memory(void* BaseAddress, size_t Size, uint32_t NewProtect, PULONG OldProtect);
	bool  ps_win32_free_memory(void* BaseAddress, size_t Size, uint32_t FreeType);

	HANDLE ps_win32_create_file(const wchar_t* FileName, uint32_t DesiredAccess, uint32_t ShareMode, 
		LPSECURITY_ATTRIBUTES SecurityAttributes, uint32_t CreationDisposition, uint32_t FlagsAndAttributes, HANDLE TemplateFile);

	bool ps_win32_get_file_size(HANDLE FileHandle, uint32_t* Size);
	bool ps_win32_read_file(HANDLE FileHandle, void* Buffer, uint32_t ToRead, uint32_t* BytesRead);

	bool ps_win32_write_file(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped);

	// todo: CreateProcess
	// unfinished due to too much overhead to spawn a process with direct system calls.
	// bool ps_win32_create_process(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, 
	//	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, 
	//	LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

	bool ps_win32_get_thread_context(HANDLE hThread, LPCONTEXT lpContext);

	bool ps_win32_set_thread_context(HANDLE hThread, LPCONTEXT lpContext);

	bool ps_win32_read_process_memory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, 
		SIZE_T* lpNumberOfBytesRead);

	bool ps_win32_write_process_memory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
		SIZE_T* lpNumberOfBytesWritten);

	DWORD ps_win32_resume_thread(HANDLE hThread);

	void* ps_win32_resolve_function(const wchar_t* ModuleName, const char* FunctionName);
	void* ps_win32_resolve_function(const char* ModuleName, const char* FunctionName);

	wchar_t* ps_win32_get_module_name_w(const wchar_t* ModuleName);

	wchar_t* ps_win32_get_current_path_w();

	wchar_t* ps_dos_path_to_nt_path_w(const wchar_t* DosPath);

	bool ps_win32_init_api();

private:
	syscall_handler* _systemCaller;
};

winapi* gWinapi = nullptr;

#define WINAPI_INIT()		gWinapi = new winapi();\
							bool Init = gWinapi->ps_win32_init_api();

#ifndef RAW_WINAPI

#define IceCloseHandle										gWinapi->ps_win32_close_handle
#define IceVirtualAlloc										gWinapi->ps_win32_allocate_memory
#define IceVirtualProtect									gWinapi->ps_win32_protect_memory
#define IceVirtualFree										gWinapi->ps_win32_free_memory
#define IceCreateFile										gWinapi->ps_win32_create_file
#define IceGetFileSize										gWinapi->ps_win32_get_file_size
#define IceReadFile											gWinapi->ps_win32_read_file
#define IceWriteFile										gWinapi->ps_win32_write_file
#define IceCreateProcess									CreateProcess // i still need to work on the direct syscall
#define IceGetThreadContext									gWinapi->ps_win32_get_thread_context
#define IceReadProcessMemory								gWinapi->ps_win32_read_process_memory
#define IceWriteProcessMemory								gWinapi->ps_win32_write_process_memory
#define IceSetThreadContext									gWinapi->ps_win32_set_thread_context
#define IceResumeThread										gWinapi->ps_win32_resume_thread

#else

#define IceCloseHandle										CloseHandle
#define IceVirtualAlloc										VirtualAlloc
#define IceVirtualProtect									VirtualProtect
#define IceVirtualFree										VirtualFree
#define IceCreateFile										CreateFile
#define IceGetFileSize										GetFileSize
#define IceReadFile											ReadFile
#define IceCreateProcess									CreateProcess
#define IceGetThreadContext									GetThreadContext
#define IceReadProcessMemory								ReadProcessMemory
#define IceWriteProcessMemory								WriteProcessMemory
#define IceSetThreadContext									SetThreadContext
#define IceResumeThread										ResumeThread

#endif // !RAW_WINAPI


#define IceGetProcAddress									gWinapi->ps_win32_resolve_function
#define IceGetCurrentPathW									gWinapi->ps_win32_get_current_path_w


