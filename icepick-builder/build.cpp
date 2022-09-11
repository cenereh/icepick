#include "build.h"

#include "filesystem.h"
#include "encrypt.h"

#include "../log.h"

/// <summary>
/// Builds the final executable
/// </summary>
/// <param name="InputPath">The input file to encrypt</param>
/// <param name="StubPath">The stub file that will take care of the encryption</param>
/// <param name="OutputPath">Where to write the final executable</param>
/// <returns>True if the write was successful, false if not.</returns>
bool build::BuildExe(const std::wstring InputPath, const std::wstring StubPath, const std::wstring OutputPath)
{
    uint8_t* InputFile, *StubFile;
    uint32_t InputSize, StubSize;

    // Read the input file
    if (!filesystem::FsReadFile(InputPath, &InputFile, InputSize))
    {
        mlog(L"Input file read failed.\n");
        return false;
    }

    // Read the stub file
    if (!filesystem::FsReadFile(StubPath, &StubFile, StubSize))
    {
        mlog(L"Stub file read failed.\n");
        return false;
    }

    icepick_crypt_data crypt_data;
    encrypt::EncryptBuffer(&crypt_data, InputFile, InputSize);

    crypt_data.SizeOfExecutable = InputSize;
    crypt_data.OffsetToExecutable = StubSize + sizeof(icepick_crypt_data);

    uint32_t WriteSize = StubSize + sizeof(icepick_crypt_data) + InputSize;
    // Allocate a new buffer contaning both files and the data structure
    uint8_t* WriteBuffer = (uint8_t*)malloc(WriteSize);

    // Copy data to the new buffer
    memcpy(WriteBuffer, StubFile, StubSize);
    memcpy(WriteBuffer + StubSize, &crypt_data, sizeof(icepick_crypt_data));
    memcpy(WriteBuffer + StubSize + sizeof(icepick_crypt_data), InputFile, InputSize);

    // Write the buffer to a valid executable on disk
    if (!filesystem::FsWriteFile(OutputPath, WriteBuffer, WriteSize))
    {
        mlog(L"File write failed.\n");
        return false;
    }

    return true;
}
