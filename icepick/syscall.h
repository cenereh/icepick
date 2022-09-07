#pragma once
#include <map>
#include <string>
#include <Windows.h>

#include "external/skCrypt.h"
#include "external/macros.h"

// The required system call could not be found
#define PC_SYSC_E_NOT_FOUND             -2

// Allocation of RWX memory using VirtualAlloc failed, check GetLastError()
#define PC_SYSC_E_ALLOC_FAILED          -3

namespace pc_system_calls
{
	auto sk_NtClose = skCrypt("NtClose");                       // NtClose
	auto sk_NtAVM	= skCrypt("NtAllocateVirtualMemory");       // NtAllocateVirtualMemory
	auto sk_NtPVM   = skCrypt("NtProtectVirtualMemory");        // NtProtectVirtualMemory
	auto sk_NtFVM	= skCrypt("NtFreeVirtualMemory");           // NtFreeVirtualMemory
	auto sk_NtCF	= skCrypt("NtCreateFile");                  // NtCreateFile
	auto sk_NtQIF	= skCrypt("NtQueryInformationFile");        // NtQueryInformationFile
	auto sk_NtRF	= skCrypt("NtReadFile");                    // NtReadFile
	auto sk_NtWFSO	= skCrypt("NtWaitForSingleObject");         // NtWaitForSingleObject
}

class syscall_handler
{
public:
	syscall_handler();
	~syscall_handler();

	bool InitSyscallTable();

	template<typename Prototype, typename... ParameterPack>
	NTSTATUS SystemCall(const char* SyscallName, ParameterPack... Params);

private:

	template<typename Prototype, typename... ParameterPack>
	NTSTATUS SystemCallInternal(unsigned long CallId, ParameterPack... Params);

	std::map<std::string, unsigned long> _syscallTable;
};

/// <summary>
/// Makes a direct syscall to kernel space
/// </summary>
/// <typeparam name="...ParameterPack">Parameters that need to be passed to the system call</typeparam>
/// <param name="SyscallName">Name of the system call that needs to be called</param>
/// <param name="...Params">All parameters required by the system call</param>
/// <returns>NTSTATUS return code of the system call</returns>
template<typename Prototype, typename ...ParameterPack>
inline NTSTATUS syscall_handler::SystemCall(const char* SyscallName, ParameterPack ...Params)
{
	// Get the system call number from the map
    auto systemCallIterator = _syscallTable.find(SyscallName);
    unsigned long SyscallNumber = 0;

    if (systemCallIterator == _syscallTable.end())
    {
        return PC_SYSC_E_NOT_FOUND;
    }
    else
    {
        SyscallNumber = systemCallIterator->second;
    }

	return SystemCallInternal<Prototype>(SyscallNumber, Params...);
}

/// <summary>
/// Internal function that executes a system call in RWX memory.
/// </summary>
/// <typeparam name="Prototype">Prototype of the system call</typeparam>
/// <typeparam name="...ParameterPack">Parameters required by the system call</typeparam>
/// <param name="CallId">Syscall number</param>
/// <param name="...Params">Parameters required by the system call</param>
/// <returns>NTSTATUS value of the system call</returns>
template<typename Prototype, typename ...ParameterPack>
inline NTSTATUS syscall_handler::SystemCallInternal(unsigned long CallId, ParameterPack ...Params)
{
	// Value returned by the system call (in the EAX register)
    NTSTATUS ReturnValue = 0x0L; 

    // ASM function template used by all system calls. 
    unsigned char systemCallStub[] = {0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3};

    // Set the correct system call number inside the ASM template
    _RAWDWR(_PTR(systemCallStub) + 0x4) = CallId;

    // todo: might trigger some avs, should be going PAGE_READWRITE -> PAGE_EXECUTE or smth
    // RWX memory address containing the ASM function template to execute 
    void* rwxMemory = VirtualAlloc(0, sizeof(systemCallStub), MEM_COMMIT, PAGE_EXECUTE_READWRITE);  

    // Check if memory was allocated properly
    if (rwxMemory == nullptr)
    {
        return PC_SYSC_E_ALLOC_FAILED;
    }

    memcpy(rwxMemory, systemCallStub, sizeof(systemCallStub));

    // RWX memory address casted to the required function prototype
    Prototype Function = Prototype(rwxMemory);

    // Call the ASM template passing the required parameters
    ReturnValue = Function(Params...);

    // Clean up memory
    VirtualFree(rwxMemory, 0, MEM_RELEASE);

    // Return
    return ReturnValue;
}
