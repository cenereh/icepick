#include "winapi.h"
#include "../ntdll/nt.h"
#include "../ntdll/prototypes.h"
#include "../external/macros.h"
#include "../../log.h"

#include <string>

#define OWN_PROCESS				_H(-1)

#ifdef WINAPI_VERBOSE

#define winlog(syscall, status)			mlog(L"Direct sytstem call %s failed with status 0x%08x.\n", syscall, status)
#define awinlog(syscall, status)		mlog_a("Direct sytstem call %s failed with status 0x%08x.\n", syscall, status)

#else

#define winlog(syscall, status)
#define awinlog(syscall, status)

#endif

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
			winlog(L"NtClose", Status)
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
			winlog(L"NtAllocateVirtualMemory", Status)
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
bool winapi::ps_win32_protect_memory(void* BaseAddress, size_t Size, uint32_t NewProtect, PULONG OldProtect)
{
	if (_systemCaller != nullptr)
	{
		NTSTATUS Status = 0x0L;
		HANDLE Handle = OWN_PROCESS;

		Status = _systemCaller->SystemCall<f_NtProtectVirtualMemory>(_SKC(pc_system_calls::sk_NtPVM), Handle, &BaseAddress,
			&Size, NewProtect, OldProtect);

		if (Status != STATUS_SUCCESS)
		{
			winlog(L"NtProtectVirtualMemory", Status)
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
			winlog(L"NtFreeVirtualMemory", Status)
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
			winlog(L"NtCreateFile", Status)
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
				winlog(L"NtGetFileSize", Status)
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
					winlog(L"NtWaitForSingleObject", Status)
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
/// Retrieves the context of the specified thread.
/// </summary>
/// <param name="hThread">A handle to the thread whose context is to be retrieved. </param>
/// <param name="lpContext">A pointer to a CONTEXT structure</param>
/// <returns>If the function succeeds, the return value is nonzero.</returns>
bool winapi::ps_win32_get_thread_context(HANDLE hThread, LPCONTEXT lpContext)
{
	NTSTATUS Status;

	Status = _systemCaller->SystemCall<f_NtGetContextThread>(pc_system_calls::sk_NtGTC, hThread, lpContext);

	if (Status != STATUS_SUCCESS)
	{
		winlog(L"NtGetContextThread", Status);
		return false;
	}
	else
	{
		return true;
	}
}

/// <summary>
/// Sets the context for the specified thread.
/// </summary>
/// <param name="hThread">A handle to the thread whose context is to be set.</param>
/// <param name="lpContext">A pointer to a CONTEXT structure that contains the context to be set in the specified thread.</param>
/// <returns>If the context was set, the return value is nonzero.</returns>
bool winapi::ps_win32_set_thread_context(HANDLE hThread, LPCONTEXT lpContext)
{
	NTSTATUS Status;

	Status = _systemCaller->SystemCall<f_NtSetContextThread>(pc_system_calls::sk_NtGTC, hThread, lpContext);

	if (Status != STATUS_SUCCESS)
	{
		winlog(L"NtSetContextThread", Status);
		return false;
	}
	else
	{
		return true;
	}
}

/// <summary>
/// Reads an external process memory
/// </summary>
/// <param name="hProcess">A handle to the process with memory that is being read.</param>
/// <param name="lpBaseAddress">A pointer to the base address in the specified process from which to read.</param>
/// <param name="lpBuffer">A pointer to a buffer that receives the contents from the address space of the specified process.</param>
/// <param name="nSize">The number of bytes to be read from the specified process.</param>
/// <param name="lpNumberOfBytesRead">A pointer to a variable that receives the number of bytes transferred into the specified buffer. If lpNumberOfBytesRead is NULL, the parameter is ignored.</param>
/// <returns>If the function succeeds, the return value is nonzero.</returns>
bool winapi::ps_win32_read_process_memory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
	NTSTATUS Status;
	Status = _systemCaller->SystemCall<f_NtReadVirtualMemory>(pc_system_calls::sk_NtRVM, hProcess, (PVOID)lpBaseAddress, 
		lpBuffer, nSize, &nSize);

	if (Status != STATUS_SUCCESS)
	{
		winlog(L"NtReadVirtualMemory", Status);
		return false;
	}
	else
	{
		if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;
		return true;
	}
}

/// <summary>
/// Writes data to an area of memory in a specified process.
/// </summary>
/// <param name="hProcess">A handle to the process memory to be modified.</param>
/// <param name="lpBaseAddress">A pointer to the base address in the specified process to which data is written.</param>
/// <param name="lpBuffer">A pointer to the buffer that contains data to be written in the address space of the specified process.</param>
/// <param name="nSize">The number of bytes to be written to the specified process.</param>
/// <param name="lpNumberOfBytesWritten">A pointer to a variable that receives the number of bytes transferred into the specified process.</param>
/// <returns>If the function succeeds, the return value is nonzero.</returns>
bool winapi::ps_win32_write_process_memory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	NTSTATUS Status;
	ULONG OldValue;
	SIZE_T RegionSize;
	PVOID Base;
	BOOL Unprotect;

	RegionSize = nSize;
	Base = lpBaseAddress;

	Status = _systemCaller->SystemCall<f_NtProtectVirtualMemory>(pc_system_calls::sk_NtPVM, hProcess, &Base, 
		&RegionSize, PAGE_EXECUTE_READWRITE, &OldValue);

	if (Status != STATUS_SUCCESS)
	{
		Unprotect = OldValue & (PAGE_READWRITE |
                                 PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY) ? FALSE : TRUE;

		if (!Unprotect)
		{
			Status = _systemCaller->SystemCall<f_NtProtectVirtualMemory>(pc_system_calls::sk_NtPVM, hProcess, &Base, 
					&RegionSize, OldValue, &OldValue);

			Status = _systemCaller->SystemCall<f_NtWriteVirtualMemory>(pc_system_calls::sk_NtWVM, hProcess, lpBaseAddress,
				(LPVOID)lpBuffer, nSize, &nSize);

			if (Status != STATUS_SUCCESS)
			{
				winlog(L"NtWriteVirtualMemory", Status);
				return false;
			}
			else
			{
				if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
				return true;
			}
		}
		else
		{
			if (OldValue & (PAGE_NOACCESS | PAGE_READONLY))
			{
				_systemCaller->SystemCall<f_NtProtectVirtualMemory>(pc_system_calls::sk_NtPVM, hProcess, &Base, &RegionSize, OldValue, 
					&OldValue);

				winlog(L"NtProtectVirtualMemory", Status);
				return false;
			}
			else
			{
				Status = _systemCaller->SystemCall<f_NtWriteVirtualMemory>(pc_system_calls::sk_NtWVM, hProcess, lpBaseAddress,
					(LPVOID)lpBuffer, nSize, &nSize);

				Status = _systemCaller->SystemCall<f_NtProtectVirtualMemory>(pc_system_calls::sk_NtPVM, hProcess, &Base, 
						&RegionSize, OldValue, &OldValue);

				if (Status != STATUS_SUCCESS)
				{
					winlog(L"NtWriteVirtualMemory");
					return false;
				}
				else
				{
					if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
					return true;
				}
			}
		}
	}
	else
	{
		winlog(L"NtProtectVirtualMemory", Status);
		return false;
	}
	
}

// todo: da fare dopo: troppa roba.
/// <summary>
/// Creates a new system process.
/// </summary>
/// <param name="lpApplicationName">Path of the application to create a process from</param>
/// <param name="lpCommandLine">Command to supply to the process</param>
/// <param name="lpProcessAttributes">Security attributes of the process.</param>
/// <param name="lpThreadAttributes">you know</param>
/// <param name="bInheritHandles">Inherit handles from parent process</param>
/// <param name="dwCreationFlags">The flags that control the priority class and the creation of the process.</param>
/// <param name="lpEnvironment">A pointer to the environment block for the new process.</param>
/// <param name="lpCurrentDirectory">The full path to the current directory for the process.</param>
/// <param name="lpStartupInfo">A pointer to a STARTUPINFO or STARTUPINFOEX structure.</param>
/// <param name="lpProcessInformation">A pointer to a PROCESS_INFORMATION structure that receives identification information about the new process.</param>
/// <returns>If the function succeeds, the return value is nonzero.</returns>
//bool winapi::ps_win32_create_process(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
//{
//	NTSTATUS Status;
//	HANDLE ProcessHandle, ThreadHandle;
//	OBJECT_ATTRIBUTES ObjectAttributes;
//	ULONG Flags;
//	BOOL InJob;
//	UNICODE_STRING ntPathU;
//	CLIENT_ID ClientId;
//	CONTEXT Context;
//	INITIAL_TEB InitialTeb;
//
//	Status = _systemCaller->SystemCall<f_NtCreateThread>(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, &ClientId, 
//		&Context, &InitialTeb, TRUE);
//
//	std::wstring ntPath = ps_dos_path_to_nt_path_w(lpApplicationName);
//
//	ntPathU.Buffer = (PWSTR)ntPath.c_str();
//	ntPathU.Length = ntPath.size() << 1;
//
//	InitializeObjectAttributes(&ObjectAttributes, &ntPathU, OBJ_CASE_INSENSITIVE, 0, 0);
//
//	Status = _systemCaller->SystemCall<f_NtCreateProcess>
//		(pc_system_calls::sk_NtCP, &ProcessHandle, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, FALSE, NULL,
//			NULL, NULL);
//
//	if (Status != STATUS_SUCCESS)
//	{
//		winlog(L"NtCreateProcess", Status);
//		return false;
//	}
//	else
//	{
//		lpProcessInformation->hProcess = ProcessHandle;
//
//	}
//}

/// <summary>
/// Resumes a thread
/// </summary>
/// <param name="hThread">Handle to the thread to resume</param>
/// <returns>If the function succeeds, the return value is the thread's previous suspend count. If the function fails, the return value is (DWORD) -1</returns>
DWORD winapi::ps_win32_resume_thread(HANDLE hThread)
{
	ULONG PreviousResumeCount;
	NTSTATUS Status;

	Status = _systemCaller->SystemCall<f_NtResumeThread>(pc_system_calls::sk_NtRT, hThread, &PreviousResumeCount);

	if (Status != STATUS_SUCCESS)
	{
		winlog("NtResumeThread", Status);
		return -1;
	}
	else
	{
		return PreviousResumeCount;
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
		mwinapi_fail(L"GetCurrentDirectoryW");
		return nullptr;
	}
}

/// <summary>
/// Gets the current working directory.
/// </summary>
/// <returns>The current working directory, or nullptr if fails.</returns>
wchar_t* winapi::ps_win32_get_current_path_w()
{
	// Fully qualified path retrieved from the PEB
	WCHAR modulePath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, modulePath);
	return modulePath;
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

