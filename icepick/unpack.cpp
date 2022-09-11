#include "unpack.h"

#include "../log.h"
#include "external/macros.h"
#include "winapi/winapi.h"
#include "encrypt.h"

#include "filesystem.h"

#define ICEPICK_SIG			0x09072022

/// <summary>
/// Parses the binary file in memory until the DWORD signature 0x09072022 is found.
/// </summary>
/// <param name="Self">Pointer to the in-memory raw executable</param>
/// <param name="Size">Size of the executable</param>
/// <returns>Pointer to the icepick_crypt_data structure.</returns>
picepick_crypt_data FindEmbeddedData(uint8_t* Self, uint32_t Size)
{
	// Parse the whole executable until the 0x09072022 signature is found

	auto sigToFind = skCrypt("kwszack");
	const char* Sig = 0;

	for (int i = 0; i < Size; i += 8)
	{
		Sig = (const char*)(Self + i);

		if (strcmp(Sig, _SKC(sigToFind)) == 0)
		{
			mlog(L"Found valid embedded data signature at 0x%p.\n", Self + i);
			return (picepick_crypt_data)(Self + i);
		}
	}

	return nullptr;
}

/// <summary>
/// Reads itself and attempts to decrypt and extract the payload.
/// </summary>
/// <param name="SizeOfPayload">: Reference that receives the size of the packed payload</param>
/// <returns>Pointer to the beginning of the payload file, or nullptr if fails.</returns>
uint8_t* unpack::UnpackPayload(uint32_t& SizeOfPayload)
{
	// Read self through the filesystem API
	uint8_t* Self;
	uint32_t Size;

#ifndef _DEBUG
	std::wstring SelfPath = IceGetCurrentPathW();
#else
	std::wstring SelfPath = L"C:\\Users\\off4a\\source\\repos\\icepick\\x64\\Debug\\output.exe";
#endif

	if (!filesystem::FsReadFile(SelfPath.c_str(), &Self, Size))
	{
		mlog(L"FsReadFile failed.\n");
		return nullptr;
	}

	// Try to find the embedded stub information, read it to retrieve a pointer to the payload.
	picepick_crypt_data CryptData = FindEmbeddedData(Self, Size);

	if (CryptData == nullptr)
	{
		mlog(L"FindEmbeddedData failed.\n");
		return nullptr;
	}

	// Copy the payload to a safe memory area which needs to be allocated.
	SizeOfPayload = CryptData->SizeOfExecutable;
	uint8_t* Payload = (uint8_t*)IceVirtualAlloc(0, SizeOfPayload, MEM_COMMIT, PAGE_READWRITE);

	if (!Payload)
	{
		mwinapi_fail(L"VirtualAlloc");
		return nullptr;
	}

	memcpy(Payload, (Self + CryptData->OffsetToExecutable), SizeOfPayload);

	// Decrypt the payload using the provided decryption key.
	encrypt::DecryptBuffer(CryptData, Payload);

	// Return
	return Payload;
}
