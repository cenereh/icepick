#include "syscall.h"

#include "external/macros.h"

syscall_handler::syscall_handler()
{
}

syscall_handler::~syscall_handler()
{
}

/// <summary>
/// Initializes the syscall table by parsing ntdll.dll
/// </summary>
/// <returns>true if the initalisation completed, false if not</returns>
bool syscall_handler::InitSyscallTable()
{
    // Skcrypt initialisation
    auto skc_ntdllName = skCrypt(L"ntdll.dll");

    // Get ntdll.dll base address from memory
    void* ntdllBaseAddress = GetModuleHandle(_SK(skc_ntdllName));

    if (ntdllBaseAddress == nullptr)
    {
        return false;
    }

    // Read PE headers from the DLL
    PIMAGE_DOS_HEADER ntdllDosHeader = PIMAGE_DOS_HEADER(ntdllBaseAddress);
    PIMAGE_NT_HEADERS ntdllNtHeaders = PIMAGE_NT_HEADERS(_PTR(ntdllDosHeader) + ntdllDosHeader->e_lfanew);

    // Check the magic number and signature (to potentially identify a bad pointer)
    if (ntdllDosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntdllNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    // Ntdll's export directory
    DWORD ntdllExportDirVA = ntdllNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; // The virtual address
    PIMAGE_EXPORT_DIRECTORY ntdllExportDir = PIMAGE_EXPORT_DIRECTORY(_PTR(ntdllBaseAddress) + ntdllExportDirVA);

    PDWORD Address = PDWORD(_PTR(ntdllBaseAddress) + ntdllExportDir->AddressOfFunctions);          // Address of functions
    PDWORD Names   = PDWORD(_PTR(ntdllBaseAddress) + ntdllExportDir->AddressOfNames);              // Names
    PWORD  Ordinal = PWORD (_PTR(ntdllBaseAddress) + ntdllExportDir->AddressOfNameOrdinals);       // Ordinals

    // Here we are going to store part of the function
    BYTE FunctionReadBuffer[32] = {0};

    // The equivalent of mov r10, rcx in byte format (aka our signature, every nt syscall has this sequence of bytes)
    const DWORD Signature = 0xb8d18b4c;

    void* AddressOfFunction = nullptr;        // The address of the function
    char* NameOfFunction = nullptr;           // Pointer to a null-terminated string that holds the name of the function
    DWORD FirstFourBytes = 0;                 // The first four bytes of the function
    DWORD SyscallNumber = 0x0;                // Points to the syscall number (a dword value)

    for (DWORD i = 0; i < ntdllExportDir->NumberOfFunctions; i++)
    {
        // Reset the buffer after each read
        memset(FunctionReadBuffer, 0, 32);

        AddressOfFunction = (void*)(_PTR(ntdllBaseAddress) + Address[Ordinal[i]]);
        NameOfFunction = (char*)(_PTR(ntdllBaseAddress) + Names[i]);

        // Copy some bytes of the function in the buffer
        memcpy(FunctionReadBuffer, AddressOfFunction, 32);

        FirstFourBytes = _RAWDWR(FunctionReadBuffer);

        // If the first four bytes match the signature
        if (FirstFourBytes == Signature)
        {
            // Read the syscall number and add to the table
            SyscallNumber = _RAWDWR(_PTR(FunctionReadBuffer) + 0x4);
            _syscallTable.emplace(NameOfFunction, SyscallNumber);
        }

    }

    // If everything is ok, return true
    return true;
}
