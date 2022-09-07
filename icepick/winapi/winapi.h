#pragma once
#include "../syscall.h"
#include <cstdint>

class winapi
{
public:
	winapi();
	~winapi();

	bool  ps_win32_close_handle(HANDLE Handle);
	
	void* ps_win32_allocate_memory(void* BaseAddress, size_t Size, uint32_t AllocType, uint32_t Protect);
	bool  ps_win32_protect_memory(void* BaseAddress, size_t Size, uint32_t NewProtect, uint32_t* OldProtect);
	bool  ps_win32_free_memory(void* BaseAddress, size_t Size, uint32_t FreeType);

	HANDLE ps_win32_create_file(const wchar_t* FileName, uint32_t DesiredAccess, uint32_t ShareMode, 
		LPSECURITY_ATTRIBUTES SecurityAttributes, uint32_t CreationDisposition, uint32_t FlagsAndAttributes, HANDLE TemplateFile);

	bool ps_win32_get_file_size(HANDLE FileHandle, uint32_t* Size);
	bool ps_win32_read_file(HANDLE FileHandle, void* Buffer, uint32_t ToRead, uint32_t* BytesRead);

	void* ps_win32_resolve_function(const wchar_t* ModuleName, const char* FunctionName);

	wchar_t* ps_win32_get_module_name_w(const wchar_t* ModuleName);
	wchar_t* ps_dos_path_to_nt_path_w(const wchar_t* DosPath);

	bool ps_win32_init_api();

private:
	syscall_handler* _systemCaller;
};

