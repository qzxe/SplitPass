#include <Windows.h>

#include "Util.h"
#include "minhook/MinHook.h"

#pragma comment(lib, "minhook/minhook.lib")

__int64 __fastcall EQU8_InitHook(BYTE* a1)
{
    return NULL;
}

void Setup()
{
    MH_Initialize();

    auto Pattern = FindPattern("4C 8B DC 55 53 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 10 49 89 7B 18 4D 89 63 20 4C 8B E1 4D 89 6B E8 48 8D 4C 24 ? 45 33 ED");

    if (Pattern)
    {
        MH_CreateHook((void*)(Pattern), EQU8_InitHook, nullptr);
        MH_EnableHook((void*)(Pattern));
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Setup();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}