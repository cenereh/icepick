#include "filesystem.h"
#include <Windows.h>

#include "../log.h"

/// <summary>
/// Reads a file from disk
/// </summary>
/// <param name="Path">: Path of the file to read.</param>
/// <param name="Buffer">: Pointer to a variable that will receive the buffer address</param>
/// <param name="Size">: Reference to a variable that will receive the buffer size.</param>
/// <returns>True if successful, false if not.</returns>
bool filesystem::FsReadFile(const std::wstring Path, uint8_t** Buffer, uint32_t& Size)
{
    HANDLE FileHandle = CreateFile(Path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        mwinapi_fail(L"CreateFile");
        return false;
    }

    Size = GetFileSize(FileHandle, nullptr);

    if (Size == 0)
    {
        mwinapi_fail(L"GetFileSize");
        return false;
    }

    *Buffer = (uint8_t*)VirtualAlloc(0, Size, MEM_COMMIT, PAGE_READWRITE);

    if (*Buffer == nullptr)
    {
        mwinapi_fail(L"VirtualAlloc");
        return false;
    }

    if (!ReadFile(FileHandle, *Buffer, Size, nullptr, nullptr))
    {
        mwinapi_fail(L"ReadFile");
        return false;
    }

    CloseHandle(FileHandle);
    return true;
}

/// <summary>
/// Writes a file to disk
/// </summary>
/// <param name="Path">: Path where to write the file to</param>
/// <param name="Buffer">: Buffer containing the content to write</param>
/// <param name="Size">: Size of the buffer.</param>
/// <returns>True if the write has been successful, false if not.</returns>
bool filesystem::FsWriteFile(const std::wstring Path, uint8_t* Buffer, uint32_t Size)
{
    HANDLE FileHandle = CreateFile(Path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        mwinapi_fail(L"CreateFile");
        return false;
    }

    if (!WriteFile(FileHandle, Buffer, Size, nullptr, nullptr))
    {
        mwinapi_fail(L"WriteFile");
        return false;
    }

    CloseHandle(FileHandle);
    return true;
}
