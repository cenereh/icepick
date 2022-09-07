#pragma once
#include <cstdint>

constexpr uint8_t k1024BitKeySz = 128;

typedef struct _icepick_crypt_data
{
	const uint32_t Id = 0x09072022;				// Signature of the crypt data.

	uint8_t EncryptionKey[k1024BitKeySz];		// XOR Encryption/Decryption key.
	uint32_t OffsetToExecutable;				// Offset to the packed executable within raw memory.
	uint32_t SizeOfExecutable;					// Size of the packed executable within raw memory

} icepick_crypt_data, *picepick_crypt_data;

static class encrypt
{
public:

	static void EncryptBuffer(picepick_crypt_data CryptData, uint8_t* Buffer, uint32_t Size);

private:

	static void GenerateKey(uint8_t* Buffer, uint32_t Size);

};

