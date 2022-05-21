#pragma once

#include "pch.h"

#include <winternl.h>

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <heapapi.h>
#pragma comment(lib, "ntdll.lib")

#include <dbghelp.h>
#include <shlobj.h>
#include <tchar.h>

#include "func.h"

void(__stdcall* ZwRaiseException)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ThreadContext, BOOLEAN HandleException);

DWORD_PTR baseTextAddress = 0;
DWORD size_of_text = 0;

DWORD WINAPI protect(PVOID address)
{
	PEXCEPTION_RECORD exr = NULL;
	CONTEXT ctx;

	ctx.Rip = TerminateThread((HANDLE)-2, 0);
	exr->NumberParameters = 2;
	exr->ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
	exr->ExceptionAddress = address;
	exr->ExceptionInformation[1] = (ULONG_PTR)address;

	ZwRaiseException(exr, &ctx, 1);
	return 0;

}

void try_protect(PVOID address)
{
	HANDLE hthread = CreateThread(NULL, 0, protect, address, NULL, 0);
	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);

}

DWORD WINAPI decrypt()
{
	AllocConsole();
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	DWORD textPageCount = 0;
	DWORD dataPageCount = 0;

	PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA(NULL);
	PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageDosHeader + imageDosHeader->e_lfanew);
	DWORD sectionCount = imageNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER imageSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)&imageNtHeaders->OptionalHeader + imageNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < sectionCount; ++i)
	{
		if (strcmp((const char*)(imageSection + i)->Name, ".text") == 0)
		{
			baseTextAddress = (DWORD_PTR)imageDosHeader + (imageSection + i)->PointerToRawData - 0x1000;
			size_of_text += ((imageSection + i)->SizeOfRawData);
			textPageCount = ((imageSection + i)->SizeOfRawData) / 0x1000;
			break;

		}
		else
		{
			PrintMessage("[+] failed to find base_address!\n");
			system("pause");
			return 0;

		}

	}
	const char* code_buffer = (const char*)calloc(1, size_of_text);
	*(PVOID*)&ZwRaiseException = GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwRaiseException");

	for(int i = 0; i < textPageCount; i++)
	{
		PVOID address = (PVOID)(baseTextAddress + i * 0x1000);

		MEMORY_BASIC_INFORMATION mbi;
		memset(&mbi, 0, sizeof(mbi));
		VirtualQuery(address, &mbi, sizeof(mbi));

		if (mbi.Protect == PAGE_NOACCESS) try_protect(address);

		memset(&mbi, 0, sizeof(mbi));
		VirtualQuery(address, &mbi, sizeof(mbi));

		if (mbi.Protect != PAGE_NOACCESS)
			memcpy((char*)code_buffer + ((DWORD_PTR)address - baseTextAddress), address, 0x1000);

		if ((i + 1) % 200 == 0 || i + 1 == textPageCount)
			PrintMessage("[+] loading: ~%c%d/%d~%c\n", 11, i + 1, textPageCount, 15);

	}

	uintptr_t gos = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x4C\x8B\x8C\xD9\x00\x00\x00\x00\x49\xC1\xEA\x20\xB8\x00\x00\x00\x00\xF7\xE3\x8B\xC3", "xxxx????xxxxx????xxxx", 0x5);

	uintptr_t uw = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x4B\x8B\xBC\xD5\x00\x00\x00\x00\x41\x8B\xC2\x2B\xC2\x45\x8B\xCA", "xxxx????xxxxxxxx", 0x5);

	uintptr_t gi = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x49\x8B\x87\x00\x00\x00\x00\x48\x85\xC0\x74\x09\x48\x8B\xB0\x00\x00\x00\x00\xEB\x07", "xxx????xxxxxxxx????xx", 0x4);

	uintptr_t lpa = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x4E\x8B\x4C\xC1\x00\x49\xC1\xEA\x20\xB8\x00\x00\x00\x00\x41\xF7\xE0\x41\x8B\xC0", "xxxx?xxxxx????xxxxxx", 0x5);
	
	uintptr_t apawn = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x48\x8B\x40\x08\xFF\x15\x00\x00\x00\x00\x90\x48\x85\xF6\x74\x14\x48\x8B\x06\x48\x8B\xCE\x48\x8B\x80\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x90", "xxxxxx????xxxxxxxxxxxxxxx????xx????x", 0x1A);

	uintptr_t root = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x48\x8B\x83\x00\x00\x00\x00\x48\x85\xC0\x74\x08\x48\x05\x00\x00\x00\x00\xEB\x07", "xxx????xxxxxxx????xx", 0x4);

	uintptr_t position = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x8B\x87\x00\x00\x00\x00\x89\x83\x00\x00\x00\x00\x48\x8B\x87\x00\x00\x00\x00\x48\x89\x83\x00\x00\x00\x00\x48\x81\xC3\x00\x00\x00\x00\x49\x3B\xDE", "xx????xx????xxx????xxx????xxx????xxx", 0x3);

	uintptr_t damage = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x48\x8B\x89\x00\x00\x00\x00\x0F\x28\xF2\x48\x8B\xFA\x48\x85\xC9", "xxx????xxxxxxxxx", 0x4);

	uintptr_t pcamera = find_pattern(code_buffer, baseTextAddress, size_of_text, "\xF2\x0F\x11\x87\x00\x00\x00\x00\x8B\x48\x08\x89\x8F\x00\x00\x00\x00\xF2\x0F\x10\x40\x00", "xxxx????xxxxx????xxxx?", 0x5);

	uintptr_t rcamera = find_pattern(code_buffer, baseTextAddress, size_of_text, "\xF2\x0F\x11\x87\x00\x00\x00\x00\x8B\x48\x14\x89\x8F\x00\x00\x00\x00\x8B\x40\x18\x89\x87\x00\x00\x00\x00", "xxxx????xxxxx????xxxxx????", 0x5);

	uintptr_t fcamera = find_pattern(code_buffer, baseTextAddress, size_of_text, "\xF2\x0F\x11\x87\x00\x00\x00\x00\x8B\x48\x14\x89\x8F\x00\x00\x00\x00\x8B\x40\x18\x89\x87\x00\x00\x00\x00", "xxxx????xxxxx????xxxxx????", 0x17);

	uintptr_t los = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x48\x8B\x00\x55\x56\x57\x41\x00\x41\x00\x48\x8D\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\xC7\x44\x24\x60", "xx?xxxx?x?xx??xxx????xxxxx", 0x1);

	uintptr_t tcomp = find_pattern(code_buffer, baseTextAddress, size_of_text, "\x48\x8B\x03\x45\x33\xC0\x48\x8B\x17\x48\x8B\xCB\x48\x8B\x80\x00\x00\x00\x00", "xxxxxxxxxxxxxxx????", 0x10);

	PrintMessage("===============================\n");

	if (gos)      PrintMessage("uintptr_t g_object_state = 0x%X\n", *(uintptr_t*)gos);
	if (uw)       PrintMessage("uintptr_t uworld_state = 0x%X\n", *(uintptr_t*)uw); else PrintMessage("failed to find uworld_state\n");
	if (uw)       PrintMessage("uintptr_t uworld_key = 0x%X\n", *(uintptr_t*)uw + 0x38); else PrintMessage("failed to find uworld_key\n");
	if (gi)       PrintMessage("uintptr_t game_instance = 0x%X\n", *(uintptr_t*)gi); else PrintMessage("failed to find game_instance\n");
	              PrintMessage("uintptr_t persistent_level = 0x%i\n", 38);
	if (lpa)      PrintMessage("uintptr_t local_player_array = 0x%X\n", *(char*)lpa); else PrintMessage("failed to find local_player_array\n");
	              PrintMessage("uintptr_t player_controller = 0x%i\n", 38);
	if (apawn)    PrintMessage("uintptr_t apawn = 0x%X\n", *(short*)apawn);
	if (root)     PrintMessage("uintptr_t root_component = 0x%X\n", *(short*)root);
	if (position) PrintMessage("uintptr_t position = 0x%X\n", *(short*)position);
	if (damage)   PrintMessage("uintptr_t damage_controller = 0x%X\n", *(short*)damage);
	if (pcamera)  PrintMessage("uintptr_t camera_position = 0x%X\n", *(short*)pcamera);
	if (rcamera)  PrintMessage("uintptr_t camera_position = 0x%X\n", *(short*)rcamera);
	if (fcamera)  PrintMessage("uintptr_t camera_position = 0x%X\n", *(short*)fcamera);
	if (los)      PrintMessage("uintptr_t line_of_sight = 0x%X\n", los - baseTextAddress);
	if (tcomp)    PrintMessage("uintptr_t team_component = 0x%X\n", *(short*)tcomp);

	PrintMessage("===============================\n");

	PrintMessage("[+] dumping!\n");

	if (write_file("C:\\v_dumps\\v_dump.exe", code_buffer, size_of_text)) PrintMessage("[+] dumped!\n");
	else PrintMessage("[-] failed to dump!\n");

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
		CloseHandle(CreateThread(NULL, 0, dump, NULL, 0, NULL));

	}
	return TRUE;

}
