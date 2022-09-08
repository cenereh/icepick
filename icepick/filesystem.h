#pragma once
#include <string>
#include <cstdint>

static class filesystem
{
public:
	static bool FsReadFile(const std::wstring Path, uint8_t** Buffer, uint32_t& Size);
	static bool FsWriteFile(const std::wstring Path, uint8_t* Buffer, uint32_t Size);
};

