#pragma once

#include "pch.h"

#include <winternl.h>

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];

} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef NTSTATUS (_stdcall* call)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext, int baseIDX);
call raise;

template <class T>
static inline std::uintptr_t calculate_relative(std::uintptr_t start, std::uint8_t sz, std::uint8_t off)
{
	return (start + sz + *reinterpret_cast<T*>(start + off));

}

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
	vsnprintf_s(buf, 4096, fmt, args);
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

void write_file(const char* name, const void* data, size_t len)
{
	FILE* f = fopen(name, "wb");

	if (f == NULL) 
	{
		PrintMessage("[-] error writing file");
		return;

	}

	size_t r = fwrite(data, 1, len, f);

	if (r != len)
		PrintMessage("[-] error writing file");

	fclose(f);
	return;

}

PVOID address = nullptr;
EXCEPTION_RECORD exr;
CONTEXT ctx;

int dbg;

HANDLE hThread;
DWORD_PTR baseTextAddress = 0;
unsigned char* v_buffer;

DWORD size_of = 0;
DWORD64 i = 0;
DWORD WINAPI decrypt()
{
	AllocConsole();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	DWORD textPageCount = 0;

	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
	PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageDosHeader + imageDosHeader->e_lfanew);
	DWORD sectionCount = imageNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER imageSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)&imageNtHeaders->OptionalHeader + imageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < sectionCount; ++i)
	{
		if (strcmp((const char*)(imageSection + i)->Name, ".text") == 0)
		{
			baseTextAddress = (DWORD_PTR)imageDosHeader + (imageSection + i)->PointerToRawData - 0x1000;
			textPageCount = ((imageSection + i)->SizeOfRawData) / 0x1000;
			break;

		}

	}

	unsigned char* code_buffer = (unsigned char*)calloc(1, textPageCount * 0x1000);

	for(int i = 0; i < textPageCount; i++)
	{
		address = (PVOID)(baseTextAddress + i * 0x1000);
		
		MEMORY_BASIC_INFORMATION mbi;
		memset(&mbi, 0, sizeof(mbi));
		VirtualQuery(address, &mbi, sizeof(mbi));

		if (mbi.Protect == PAGE_NOACCESS)
		{
			memset(&exr, 0, sizeof(EXCEPTION_RECORD));
			RtlCaptureContext(&ctx);

			ctx.Rip = 0;
			exr.ExceptionAddress = (PVOID)address;
			exr.NumberParameters = 2;
			exr.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
			exr.ExceptionInformation[1] = (ULONG_PTR)address;
			raise(&exr, &ctx, 0);

		}

		memcpy((unsigned char*)code_buffer + ((DWORD_PTR)address - baseTextAddress), address, 0x1000);

		if ((i + 1) % 200 == 0 || i + 1 == textPageCount)
			PrintMessage("[+] sections decrypted: ~%c%d/%d~%c\n", 11, i + 1, textPageCount, 15);

		size_of = textPageCount * 0x1000;

	}
	write_file("C:\\v_dumps\\v_dump.exe", code_buffer, size_of);
	
	PrintMessage("[+] successfully dumped!\n");

	return 0;

}

DWORD WINAPI dump(LPVOID lpParameter)
{
	decrypt();
	return 0;

}

BOOL WINAPI DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		const auto ki_dispatcher = reinterpret_cast<std::uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher"));
		const auto exception_dispatch = calculate_relative<std::int32_t>(ki_dispatcher + 0x29, 5, 1);
		const auto rtlp = calculate_relative<std::int32_t>(exception_dispatch + 0x66, 5, 1);

		raise = (call)(rtlp);

		CloseHandle(CreateThread(NULL, 0, dump, NULL, 0, NULL));

	}
	return TRUE;

}

