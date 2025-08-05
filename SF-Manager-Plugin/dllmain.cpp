// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Declare external cleanup function
extern "C" void CleanupSecurityDriver();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Plugin loaded - no initialization needed here
        // Unity will call InitializeSecurityDriver explicitly
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // Clean up when the process exits
        CleanupSecurityDriver();
        break;
    }
    return TRUE;
}

