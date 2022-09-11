#include "mapper.h"

#include "winapi/winapi.h"
#include "../log.h"

using ExecMain = void(*)();

typedef struct BASE_RELOCATION_BLOCK {

	DWORD PageAddress;
	DWORD BlockSize;

} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;


/// <summary>
/// Manually maps the image inside the process space. Only works with UNMANAGED 64bit binaries (no .NET).
/// </summary>
/// <param name="Image">Pointer to the image loaded in memory.</param>
/// <returns>False if the process mapping failed, otherwise runs the image and returns true once the image has exited.</returns>
bool mapper::UnmanagedManualMap(uint8_t* Image)
{
	bool HasExceptionDirectory = false;
	bool RequiresRelocation = false;

	PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Image;
	PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)(Image + Dos->e_lfanew);

	if (Dos->e_magic != IMAGE_DOS_SIGNATURE || Nt->Signature != IMAGE_NT_SIGNATURE)
	{
		mlog(L"The image supplied to manual mapping is not a valid PE image: E_MAGIC 0x%04x, Signature 0x%08x.\n",
			Dos->e_magic, Nt->Signature);
		return false;
	}

	DWORD_PTR SizeOfImage = Nt->OptionalHeader.SizeOfImage;
	DWORD_PTR BaseAddress = (DWORD_PTR)IceVirtualAlloc((void*)Nt->OptionalHeader.ImageBase, SizeOfImage, 
		MEM_COMMIT, PAGE_READWRITE);

	if (!BaseAddress)
	{
		mlog(L"ImageBase allocation failed: allocating to a random address...\n");

		BaseAddress = (DWORD_PTR)IceVirtualAlloc(0, SizeOfImage, MEM_COMMIT, PAGE_READWRITE);

		if (!BaseAddress)
		{
			mlog(L"Random base address allocation failed.\n");
			return false;
		}

		RequiresRelocation = true;
	}

	DWORD_PTR MapDelta = BaseAddress - Nt->OptionalHeader.ImageBase;

	memcpy((void*)BaseAddress, Image, Nt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER CurrentPeSection = IMAGE_FIRST_SECTION(Nt);

	for (size_t i = 0; i < Nt->FileHeader.NumberOfSections; i++)
	{
		// todo: add empty section checks

		void* Dest = (void*)(BaseAddress + CurrentPeSection->VirtualAddress);
		void* Ptr = (void*)(Image + CurrentPeSection->PointerToRawData);

		memcpy(Dest, Ptr, CurrentPeSection->SizeOfRawData);
		CurrentPeSection++;
	}

	DWORD RelocationIndex = 0;

	IMAGE_DATA_DIRECTORY Relocations = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR RelocationTable = Relocations.VirtualAddress + (DWORD_PTR)BaseAddress, 
		RelocationsProcessed = 0, 
		RelocationsCount = 0;

	while (RelocationsProcessed < Relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(RelocationTable + RelocationsProcessed);
		RelocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);

		if (relocationBlock->BlockSize)
		{
			RelocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY RelocationEntries = (PBASE_RELOCATION_ENTRY)(RelocationTable + RelocationsProcessed);

			for (int i = 0; i < RelocationsCount; i++)
			{
				RelocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
				if (RelocationEntries[i].Type == 0) continue;

				DWORD_PTR RelocationRva = relocationBlock->PageAddress + RelocationEntries[i].Offset;
				DWORD_PTR AddressToPatch = *(DWORD_PTR*)(BaseAddress + RelocationRva);
				AddressToPatch += MapDelta;
				memcpy((void*)(BaseAddress + RelocationRva), &AddressToPatch, sizeof(DWORD_PTR));
			}
		}
		else
		{
			break;
		}
	}

	DWORD_PTR ImportTableIndex = 0;

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = nullptr;
	IMAGE_DATA_DIRECTORY ImportDirectory = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ImportDirectory.VirtualAddress + BaseAddress);

	LPCSTR LibraryName = "";

	while (ImportDescriptor->Name != 0)
	{
		LibraryName = (LPCSTR)(ImportDescriptor->Name + BaseAddress);
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(BaseAddress + ImportDescriptor->FirstThunk);
		PIMAGE_IMPORT_BY_NAME FunctionName = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + thunk->u1.AddressOfData);

		while (thunk->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
			{
				LPCSTR Ordinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
				thunk->u1.Function = (DWORD_PTR)IceGetProcAddress(LibraryName, Ordinal);

				if (!thunk->u1.Function)
				{
					mlog_a("Function with ordinal %s in %s could not be resolved (%d).\n",
						Ordinal, LibraryName, GetLastError());
					return false;
				}
			}
			else
			{
				FunctionName = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + thunk->u1.AddressOfData);
				thunk->u1.Function = (DWORD_PTR)IceGetProcAddress(LibraryName, FunctionName->Name);

				if (!thunk->u1.Function)
				{
					mlog_a("Function with name %s in %s could not be resolved (%d).\n",
						FunctionName, LibraryName, GetLastError());
					return false;
				}
			}

			thunk++;
		}

		ImportDescriptor++;
	}

	PIMAGE_DATA_DIRECTORY TLS = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (TLS->Size && TLS->VirtualAddress)
	{
		PIMAGE_TLS_DIRECTORY TLSDirectory = (PIMAGE_TLS_DIRECTORY)(BaseAddress + TLS->VirtualAddress);
		PIMAGE_TLS_CALLBACK* TLSCallback  = (PIMAGE_TLS_CALLBACK*)(TLSDirectory->AddressOfCallBacks);

		while (TLSCallback && *TLSCallback)
		{
			(*TLSCallback)((PVOID)BaseAddress, DLL_PROCESS_ATTACH, 0);
			TLSCallback++;
		}
	}

	DWORD oldp;

	// todo: this is bad, make each page have its proper access permissions!!
	IceVirtualProtect((void*)BaseAddress, SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	ExecMain main = (ExecMain)(BaseAddress + Nt->OptionalHeader.AddressOfEntryPoint);
	main();

	return true;
}

/// <summary>
/// Maps an executable inside another legitimate process. Only works with UNMANAGED 64bit binaries (no .NET)
/// </summary>
/// <param name="proc">Process to inject into.</param>
/// <param name="Image">Pointer to an image loaded in memory</param>
/// <returns>Nonzero if successful.</returns>
bool mapper::UnmanagedProcessInjection(ProcessToInject proc, uint8_t* Image)
{
	return false;
}

/// <summary>
/// Maps an executable inside another legitimate process. Only works with UNMANAGED 32bit binaries (no .NET)
/// </summary>
/// <param name="proc">Process to inject into.</param>
/// <param name="Image">Pointer to an image loaded in memory</param>
/// <returns>Nonzero if successful.</returns>
bool mapper::UnmanagedX86ProcessInjection(ProcessToInject proc, uint8_t* Image)
{
	return false;
}

/// <summary>
/// Maps an executable inside the embedded .NET stub. Only works with MANAGED 64bit binaries.
/// </summary>
/// <param name="Image">Pointer to an image loaded in memory</param>
/// <returns>Nonzero if successful.</returns>
bool mapper::ManagedProcessInjection(uint8_t* Image)
{
	return false;
}

/// <summary>
/// Maps an executable inside the embedded .NET stub. Only works with MANAGED 32bit binaries.
/// </summary>
/// <param name="Image">Pointer to an image loaded in memory</param>
/// <returns>Nonzero if successful.</returns>
bool mapper::ManagedX86ProcessInjection(uint8_t* Image)
{
	return false;
}
