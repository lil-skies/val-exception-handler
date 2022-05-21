#pragma once

#include<Windows.h>

void PrintSingleCharacter(char c)
{
	DWORD written;
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), &c, 1, &written, NULL);

}

void PrintMessage(const char* fmt, ...)
{
	char buf[4096];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, 4096, fmt, args);
	char* bufptr = buf;
	while (*bufptr)
	{
		if (*bufptr == '~')
		{
			++bufptr;
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), *bufptr);

		}
		else
		{
			PrintSingleCharacter(*bufptr);
		}
		++bufptr;

	}
	PrintSingleCharacter('\n');
	va_end(args);

}


bool write_file(const char* name, const void* data, size_t len)
{
	FILE* f = fopen(name, "wb");

	if (f == NULL)
	{
		PrintMessage("[-] error writing file");
		return false;

	}

	size_t r = fwrite(data, 1, len, f);

	if (r != len)
	{
		PrintMessage("[-] error writing file");
		return false;

	}
	fclose(f);
	return true;

}

uintptr_t find_pattern(const char* block, uint64_t startAddress, uint64_t size, const char* pattern, const char* mask, int offset)
{
	size_t pos = 0;
	auto maskLength = strlen(mask);

	for (int j = 0; j < size; j++)
	{
		if (block[j] == pattern[pos] || mask[pos] == '?')
		{
			if (mask[pos + 1] == '\0')
			{
				PrintMessage("[+] pattern scan succeeded!\n");
				return startAddress + j - maskLength + offset;

			}
			pos++;

		}
		else pos = 0;

	}
	PrintMessage("[-] pattern scan failed!\n");
	return 0;

}

