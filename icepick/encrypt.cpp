#include "encrypt.h"
#include <random>
#include <time.h>

/// <summary>
/// Encrypts a buffer using XOR encryption
/// </summary>
/// <param name="CryptData">: Pointer to a picepick_crypt_data structure that will receive the encryption key.</param>
/// <param name="Buffer">: Buffer of data to encrypt.</param>
/// <param name="Size">: Size of the buffer of data.</param>
void encrypt::EncryptBuffer(picepick_crypt_data CryptData, uint8_t* Buffer, uint32_t Size)
{
	GenerateKey(CryptData->EncryptionKey, k1024BitKeySz);

	int KeyIndex = 0;

	for (unsigned int i = 0; i < Size; i++, KeyIndex++)
	{
		Buffer[i] ^= CryptData->EncryptionKey[KeyIndex];

		if (KeyIndex == k1024BitKeySz)
			KeyIndex = 0;
	}
}

/// <summary>
/// Decryts a buffer of data using XOR encryption
/// </summary>
/// <param name="CryptData">: Pointer to a picepick_crypt_data structure that holds the encryption key and size.</param>
/// <param name="Buffer">: Buffer to decrypt.</param>
void encrypt::DecryptBuffer(picepick_crypt_data CryptData, uint8_t* Buffer)
{
	int KeyIndex = 0;

	for (unsigned int i = 0; i < CryptData->SizeOfExecutable; i++, KeyIndex++)
	{
		Buffer[i] ^= CryptData->EncryptionKey[KeyIndex];

		if (KeyIndex == k1024BitKeySz)
			KeyIndex = 0;
	}
}

/// <summary>
/// Generates an encryption key.
/// </summary>
/// <param name="Buffer">: Buffer that will receive the encryption key.</param>
/// <param name="Size">: Buffer size.</param>
void encrypt::GenerateKey(uint8_t* Buffer, uint32_t Size)
{
	srand(time(NULL));

	for (int i = 0; i < Size; i++)
	{
		Buffer[i] = rand() % 0xFF + 0x01;
	}
}
