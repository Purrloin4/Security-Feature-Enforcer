/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks for manual mapped version.
    This version is designed specifically for kdmapper and uses pure WDM.
    It avoids all exception-prone operations to prevent KMODE_EXCEPTION_NOT_HANDLED.

Environment:

    Kernel-mode Driver

--*/

#include "driver.h"
#include <ntddk.h>

// UEFI function declaration
NTSYSAPI NTSTATUS NTAPI ExGetFirmwareEnvironmentVariable(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _Out_writes_bytes_to_opt_(*ValueLength, *ValueLength) PVOID Value,
    _Inout_ PULONG ValueLength,
    _Out_opt_ PULONG Attributes
);

// Simple global variable to store our "Secure Boot" status
static BOOLEAN g_SecureBootStatus = FALSE;

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DbgPrintEx(0, 0, "[SF-Enforcer-MM] Hello world! Driver loaded successfully\n");
    
    // UEFI Secure Boot check
    UNICODE_STRING varName;
    RtlInitUnicodeString(&varName, L"SecureBoot");
    
    UCHAR secureBootValue = 0;
    // EFI_GLOBAL_VARIABLE GUID: {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
    GUID EFI_GLOBAL_VARIABLE = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } };
    ULONG valueLength = sizeof(secureBootValue);
    
    NTSTATUS ntStatus = ExGetFirmwareEnvironmentVariable(&varName, &EFI_GLOBAL_VARIABLE, &secureBootValue, &valueLength, NULL);
    
    if (NT_SUCCESS(ntStatus)) {
        if (secureBootValue == 1) {
            g_SecureBootStatus = TRUE;
            DbgPrintEx(0, 0, "[SF-Enforcer-MM] UEFI Secure Boot: ENABLED (verified via UEFI variable)\n");
        } else {
            DbgPrintEx(0, 0, "[SF-Enforcer-MM] UEFI Secure Boot: DISABLED (verified via UEFI variable)\n");
        }
        DbgPrintEx(0, 0, "[SF-Enforcer-MM] UEFI SecureBoot variable value: %u\n", secureBootValue);
    }
    else {
        DbgPrintEx(0, 0, "[SF-Enforcer-MM] UEFI access failed: 0x%X\n", ntStatus);
    }
    DbgPrintEx(0, 0, "[SF-Enforcer-MM] Final Secure Boot Status: %s\n", g_SecureBootStatus ? "ENABLED" : "DISABLED");
    
    return STATUS_SUCCESS;
}