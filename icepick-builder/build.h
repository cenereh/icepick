#pragma once
#include <string>

static class build
{
public:
	static bool BuildExe(const std::wstring InputPath, const std::wstring StubPath, const std::wstring OutputPath);
};

