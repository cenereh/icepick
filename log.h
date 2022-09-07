#pragma once
#include <stdio.h>
#include <string>
#include <chrono>
#include <time.h>
#include <Windows.h>

static class utils
{
public:
	/// <summary>
	/// Check if a directory exists on disk
	/// </summary>
	/// <param name="szPath">Path of the directory to check</param>
	/// <returns>true if it exists, false if not</returns>
	static inline BOOL DirectoryExists(LPCTSTR szPath)
	{
		  DWORD dwAttrib = GetFileAttributes(szPath);

		  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
				 (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	/// <summary>
	/// Creates a new directory on disk
	/// </summary>
	/// <param name="szPath">Directory path</param>
	/// <returns>true if successful, false if not (check GetLastError)</returns>
	static inline bool MakeDirectory(LPCTSTR szPath)
	{
		return CreateDirectory(szPath, nullptr);
	}

	/// <summary>
	/// Gets the current working directory.
	/// </summary>
	/// <returns>String contaning the current directory path.</returns>
	static inline const std::wstring GetCurrentDir()
	{
		WCHAR buf[MAX_PATH];
		GetCurrentDirectory(MAX_PATH, buf);
		return buf;
	}
};

/// <summary>
/// Class used for logging.
/// </summary>
class icepicklog
{
public:
	 /// <summary>
	 /// Initializes the logging module.
	 /// </summary>
	 /// <returns>true if OK, false if not</returns>
	 inline bool init()
	 {
		if (!utils::DirectoryExists(L"logs"))
			utils::MakeDirectory(L"logs");

		int errno_int = 0;

		auto time = std::chrono::system_clock::now();
		std::time_t t = std::chrono::system_clock::to_time_t(time);

		char timestr[26];
		ctime_s(timestr, 26, &t);

		timestr[24] = '\0';

		removeSpaces(timestr);

		m_FileName = "logs\\icepick_log_" + std::string(timestr) + ".txt";
		fopen_s(&fp, m_FileName.c_str(), "a+");

		_get_errno(&errno_int);

		// once the file is created, close the stream.
		// the stream will be reopened each time a debug line has to be written to it

		if (fp != NULL)
			fclose(fp);

		if (errno_int)
			return false;
		else
			return true;
	 }

	 /// <summary>
	 /// Writes an ASCII string to file.
	 /// </summary>
	 /// <typeparam name="...T">Variadic parameters type</typeparam>
	 /// <param name="string">String to write</param>
	 /// <param name="...Params">Variadic args following the string</param>
	 template<typename... T>inline void debug_fprintf(const char* string, T... Params) 
	 { 
		 // open the file for writing
		 fopen_s(&fp, m_FileName.c_str(), "a+");

		 // write the debug line to the file
		 fprintf(fp, string, Params...); 

		 // close the stream
		 if (fp != NULL)
			fclose(fp);
	 }

	 /// <summary>
	 /// Writes a UTF-16 string to a file.
	 /// </summary>
	 /// <typeparam name="...T">Variadic parameters type</typeparam>
	 /// <param name="string">Wide string to write</param>
	 /// <param name="...Params">Variadic args following the string</param>
	 template<typename... T>inline void debug_fwprintf(const wchar_t* string, T... Params) 
	 { 
		 // open the file for writing
		 fopen_s(&fp, m_FileName.c_str(), "a+");

		 // write the debug line to the file
		 fwprintf(fp, string, Params...);

		 // close the stream
		 if (fp != NULL)
			fclose(fp);
	 }

	 /// <summary>
	 /// Writes a UTF-16 string to the console
	 /// </summary>
	 /// <typeparam name="...T">Variadic parameters type</typeparam>
	 /// <param name="string">Wide string to write</param>
	 /// <param name="...Params">Variadic args following the string</param>
	 template<typename... T>inline void debug_wprintf(const wchar_t* string, T... Params) 
	 { 
		 // write the debug line to the stdout or somethig idk
		 wprintf(string, Params...);
	 }

private:

	void removeSpaces(char *str)
	{
		for (int i = 0; i < strlen(str); i++)
			if (str[i] == ' ' || str[i] == ':')
				str[i] = '_';
	}

	FILE* fp;
	std::string m_FileName;
};

icepicklog* gLogInst = nullptr;

#ifdef _DEBUG
#define mlog(cont, ...)				gLogInst->debug_fwprintf(cont, __VA_ARGS__)
#define clog(cont, ...)				gLogInst->debug_wprintf(cont, __VA_ARGS__)

#define mwinapi_fail(call)			gLogInst->debug_fwprintf(L"%s failed with error code %d.\n", call, GetLastError())
#define cwinapi_fail(call)			gLogInst->debug_fprintf(L"%s failed with error code %d.\n", call, GetLastError())

#define LOG_INIT()					gLogInst = new icepicklog();\
									gLogInst->init();
#else
#define mlog(cont, ...)	
#define clog(cont, ...) 

#define mwinapi_fail(call)
#define cwinapi_fail(call)

#define LOG_INIT()		
#endif