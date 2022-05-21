#pragma once
#include <Windows.h>

template <class T>
static inline uintptr_t calculate_relative(std::uintptr_t start, std::uint8_t sz, std::uint8_t off)
{
    return (start + sz + *reinterpret_cast<T*>(start + off));

}

PVOID(_stdcall* NtQueryProcess)
(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL

);

DWORD process_cookie()
{
    DWORD cookie = 0;
    DWORD return_length = 0;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    *(PVOID*)&NtQueryProcess = GetProcAddress(ntdll, "NtQueryInformationProcess"); 
    
    NtQueryProcess(GetModuleHandle(NULL), (PROCESSINFOCLASS)0x24, &cookie, sizeof(cookie), &return_length);

    return cookie;

}

#define ROR(x, y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))
DWORD decode_pointer(DWORD pointer) 
{
    static ULONG fprocess_cookie = 0;
    if (!fprocess_cookie) 
    {
        fprocess_cookie = process_cookie();
        if (!fprocess_cookie) 
        {
            return 0;

        }

    }
    unsigned char shift_size = 0x20 - (fprocess_cookie & 0x1f);
    return ROR(pointer, shift_size) ^ fprocess_cookie;

}

DWORD get_veh_offset()
{
    HMODULE ntdll = LoadLibrary("ntdll.dll");


}
