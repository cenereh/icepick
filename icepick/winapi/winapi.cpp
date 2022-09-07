#include "winapi.h"
#include "../ntdll/nt.h"
#include "../ntdll/prototypes.h"
#include "../external/macros.h"

#include <string>

#define OWN_PROCESS				_H(-1)

winapi::winapi() :
	_systemCaller(nullptr)
{
}

winapi::~winapi()
{
	delete _systemCaller;
}

/// <summary>
/// Closes an open handle.
/// </summary>
/// <param name="Handle">Open handle to close</param>
/// <returns>true if successful, false if not.</returns>
bool winapi::ps_win32_close_handle(HANDLE Handle)
{
	// Check if the system caller has been initalised
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;

		Status = _systemCaller->SystemCall<f_NtClose>(_SKC(pc_system_calls::sk_NtClose), Handle);

		if (Status != STATUS_SUCCESS)
		{
			// Should probably log the error here
			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Allocates a block of memory in the process memory space
/// </summary>
/// <param name="BaseAddress">Base address of the block of memory: can be NULL.</param>
/// <param name="Size">Size of the block of memory to allocate</param>
/// <param name="AllocType">Type of allocation (refer to https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)</param>
/// <param name="Protect">Type of page protection (refer to https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)</param>
/// <returns>Base address of the allocated block of memory if allocated, nullptr if an error occured</returns>
void* winapi::ps_win32_allocate_memory(void* BaseAddress, size_t Size, uint32_t AllocType, uint32_t Protect)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		HANDLE Handle = OWN_PROCESS;

		Status = _systemCaller->SystemCall<f_NtAllocateVirtualMemory>(_SKC(pc_system_calls::sk_NtAVM), Handle, &BaseAddress, 
			_UL_64(0), &Size, AllocType, Protect);

		if (Status != STATUS_SUCCESS)
		{
			// Should probably log the error here
			return nullptr;
		}
		else
		{
			return BaseAddress;
		}
	}
	else
	{
		return nullptr;
	}
	
}

/// <summary>
/// Changes protection assigned to a block of memory in the process address space.
/// </summary>
/// <param name="BaseAddress">Base address of the block of memory</param>
/// <param name="Size">Size of the block of memory to change protection of</param>
/// <param name="NewProtect">New protection mask to assign</param>
/// <param name="OldProtect">Pointer to a variable that will hold the old protection mask</param>
/// <returns>true if memory protection has been changed successfully, false if not</returns>
bool winapi::ps_win32_protect_memory(void* BaseAddress, size_t Size, uint32_t NewProtect, uint32_t* OldProtect)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		HANDLE Handle = OWN_PROCESS;

		Status = _systemCaller->SystemCall<f_NtProtectVirtualMemory>(_SKC(pc_system_calls::sk_NtPVM), Handle, &BaseAddress,
			&Size, NewProtect, OldProtect);

		if (Status != STATUS_SUCCESS)
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		return false;
	}
	
}

/// <summary>
/// Frees a block of memory in the process address space
/// </summary>
/// <param name="BaseAddress">Base address of allocated memory</param>
/// <param name="Size">Size to free, must be NULL if FreeType=MEM_RELEASE</param>
/// <param name="FreeType">Type of release (check https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)</param>
/// <returns>true if the block of memory was freed, false if not</returns>
bool winapi::ps_win32_free_memory(void* BaseAddress, size_t Size, uint32_t FreeType)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		HANDLE Handle = OWN_PROCESS;

		Status = _systemCaller->SystemCall<f_NtFreeVirtualMemory>(_SKC(pc_system_calls::sk_NtFVM), Handle, &BaseAddress,
			&Size, FreeType);

		if (Status != STATUS_SUCCESS)
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Opens an handle to an existing or not existing file.
/// Further info: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
/// </summary>
/// <param name="FileName">Name of the file to open</param>
/// <param name="DesiredAccess">Desired access.</param>
/// <param name="ShareMode">Share mode between processes</param>
/// <param name="SecurityAttributes">Security attributes</param>
/// <param name="CreationDisposition">How the file is created or disposed</param>
/// <param name="FlagsAndAttributes">Various flags (use FILE_FLAG_DELETE_ON_CLOSE to delete the file when closing the handle)</param>
/// <param name="TemplateFile">Unused, set it to NULL.</param>
/// <returns>An handle to the file if execution is ok, INVALID_HANDLE_VALUE (-1) if an error occured</returns>
HANDLE winapi::ps_win32_create_file(const wchar_t* FileName, uint32_t DesiredAccess, uint32_t ShareMode, LPSECURITY_ATTRIBUTES SecurityAttributes, uint32_t CreationDisposition, uint32_t FlagsAndAttributes, HANDLE TemplateFile)
{
	if (_systemCaller != nullptr)
	{
		OBJECT_ATTRIBUTES objectAttributes = {};
		IO_STATUS_BLOCK ioStatusBlock = {};
		UNICODE_STRING ntPath = {};
		PLARGE_INTEGER allocSize = {};
		HANDLE Handle = INVALID_HANDLE_VALUE;
		NTSTATUS Status = 0x0L;
		ULONG FileAttributes = 0, Flags = 0;
		PVOID EaBuffer = 0;
		ULONG EaLength = 0;

		switch (CreationDisposition)
		{
		case CREATE_NEW:
			CreationDisposition = FILE_CREATE;
			break;
		case CREATE_ALWAYS:
			CreationDisposition = FILE_OVERWRITE_IF;
			break;
		case OPEN_EXISTING:
			CreationDisposition = FILE_OPEN;
			break;
		case OPEN_ALWAYS:
			CreationDisposition = FILE_OPEN_IF;
			break;
		case TRUNCATE_EXISTING:
			CreationDisposition = FILE_OVERWRITE;
			break;
		default:
			return INVALID_HANDLE_VALUE;
		}

		// I'll probably never use this but it is cool ok
		if (FlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
		{
			Flags |= FILE_DELETE_ON_CLOSE;
			DesiredAccess |= DELETE;
		}

		// Tell that the file is not a directory
		Flags |= FILE_NON_DIRECTORY_FILE;

		std::wstring NtPathAsString = L"\\??\\" + std::wstring(FileName);
		
		ntPath.Buffer = (wchar_t*)(NtPathAsString.c_str());
		ntPath.Length = NtPathAsString.size() << 1;
		ntPath.MaximumLength = NtPathAsString.size();

		InitializeObjectAttributes(&objectAttributes, &ntPath, 0, NULL, NULL);

		// Could be useful
		if (SecurityAttributes != nullptr)
		{
			if (SecurityAttributes->bInheritHandle == true)
			{
				objectAttributes.Attributes |= OBJ_INHERIT;
			}

			objectAttributes.SecurityDescriptor = SecurityAttributes->lpSecurityDescriptor;
		}

		Status = _systemCaller->SystemCall<f_NtCreateFile>(_SKC(pc_system_calls::sk_NtCF), &Handle, DesiredAccess, &objectAttributes,
			&ioStatusBlock, PLARGE_INTEGER(NULL), FileAttributes, ShareMode, CreationDisposition, Flags, EaBuffer, EaLength);

		if (Status != STATUS_SUCCESS)
		{
			return INVALID_HANDLE_VALUE;
		}
		else
		{
			return Handle;
		}

	}
	else
	{
		return INVALID_HANDLE_VALUE;
	}
}

/// <summary>
/// Gets the size of a file on disk in bytes.
/// </summary>
/// <param name="FileHandle">Open handle to a file</param>
/// <param name="Size">Pointer to a variable that will hold the file size</param>
/// <returns>true if successful, false if not</returns>
bool winapi::ps_win32_get_file_size(HANDLE FileHandle, uint32_t* Size)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		FILE_STANDARD_INFORMATION fileStandardInformation = {};
		IO_STATUS_BLOCK ioStatusBlock = {};

		Status = _systemCaller->SystemCall<f_NtQueryInformationFile>(_SKC(pc_system_calls::sk_NtQIF), FileHandle,
			&ioStatusBlock, &fileStandardInformation, sizeof(fileStandardInformation), FileStandardInformation);

		if (Status != STATUS_SUCCESS)
		{
			return false;
		}
		else
		{
			if (Size != nullptr)
			{
				*Size = fileStandardInformation.EndOfFile.QuadPart;
				return true;
			}
			else
			{
				// Bad pointer passed as parameter, return false
				return false;
			}
		}
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Reads a file on disk to a buffer allocated in memory
/// </summary>
/// <param name="FileHandle">Open handle to the file on disk</param>
/// <param name="Buffer">Space of allocated memory</param>
/// <param name="ToRead">Size of the buffer</param>
/// <param name="BytesRead">(Optional) Number of bytes read</param>
/// <returns>true if the read operation is successful, false if not</returns>
bool winapi::ps_win32_read_file(HANDLE FileHandle, void* Buffer, uint32_t ToRead, uint32_t* BytesRead)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		IO_STATUS_BLOCK ioStatusBlock = {};
		LARGE_INTEGER Offset = {};
		PLARGE_INTEGER Timeout = NULL;
		PIO_APC_ROUTINE ApcRoutine = NULL;
		ULONG Key = NULL;
		HANDLE Event = NULL;
		PVOID ApcContext = NULL;

		if (BytesRead != nullptr)
			*BytesRead = 0;

		Status = _systemCaller->SystemCall<f_NtReadFile>(_SKC(pc_system_calls::sk_NtRF), FileHandle, Event,
			ApcRoutine, ApcContext, &ioStatusBlock, Buffer, ToRead, &Offset, &Key);

		if (Status != STATUS_PENDING && Status != STATUS_END_OF_FILE)
		{
			// The call has failed
			return false;
		}
		else
		{
			if (Status == STATUS_PENDING)
			{
				// Waits for the task to finish
				Status = _systemCaller->SystemCall<f_NtWaitForSingleObject>(_SKC(pc_system_calls::sk_NtWFSO), FileHandle,
					false, PLARGE_INTEGER(NULL));

				if (Status != STATUS_SUCCESS)
				{
					// Not sure what to do if WaitForSingleObject fails
					return false;
				}
				else
				{
					Status = ioStatusBlock.Status;
				}
			}

			// The file has been read successfully
			if (BytesRead != nullptr)
				*BytesRead = ioStatusBlock.Information;

			return true;
		}
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Loads a function from a DLL loaded in the PEB.
/// </summary>
/// <param name="ModuleName">Name of the DLL to load the function from</param>
/// <param name="FunctionName">Name of the function to load</param>
/// <returns></returns>
void* winapi::ps_win32_resolve_function(const wchar_t* ModuleName, const char* FunctionName)
{
	return GetProcAddress(GetModuleHandle(ModuleName), FunctionName);
}

/// <summary>
/// Retrieves a fully qualified NT path of a loaded module in memory
/// </summary>
/// <param name="ModuleName">The name of the module to search. If NULL, it will retrieve the fully qualified NT path of
/// the current executable</param>
/// <returns>a NULL terminated unicode string if the module has been found, or nullptr if not.</returns>
wchar_t* winapi::ps_win32_get_module_name_w(const wchar_t* ModuleName)
{
	// Fully qualified path retrieved from the PEB
	WCHAR modulePath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, modulePath);

	if (modulePath != nullptr)
	{
		// The path must be converted to a NT path format ("\\??\\path" for example)
		return ps_dos_path_to_nt_path_w(modulePath);
	}
	else
	{
		return nullptr;
	}
}

/// <summary>
/// Converts a DOS path to a NT valid path
/// </summary>
/// <param name="DosPath">DOS path to convert</param>
/// <returns>Pointer to a unicode string which is a valid NT path</returns>
wchar_t* winapi::ps_dos_path_to_nt_path_w(const wchar_t* DosPath)
{
	// NT Path prefix
	wchar_t NtPath[MAX_PATH] = L"\\??\\";

	wcscat_s(NtPath, DosPath);

	return NtPath;
}

/// <summary>
/// Initialises the system caller.
/// </summary>
/// <returns>true if successful, false if not</returns>
bool winapi::ps_win32_init_api()
{
	_systemCaller = new syscall_handler();
	bool initResult = _systemCaller->InitSyscallTable();

	return initResult;
}

