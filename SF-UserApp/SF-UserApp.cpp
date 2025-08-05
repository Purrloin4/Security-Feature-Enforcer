#include <initguid.h>
#include <Windows.h>
#include <stdio.h>
#include <tbs.h> // Include the TBS header
#include "..\\SF-Enforcer\\Public.h"

#pragma comment (lib, "Tbs.lib") // Link against the TBS library

void PrintSecurityStatus(const SYSTEM_SECURITY_STATUS* status)
{
    printf("\n--- System Security Status ---\n");
    printf("Code Integrity Check: Memory Integrity (HVCI):              %s\n", status->IsHvciEnabled ? "[+] ENABLED" : "[-] DISABLED");
    printf("Code Integrity Check: DSE (Driver Sig. Enf.):               %s\n", status->IsDseEnabled ? "[+] ENABLED" : "[-] DISABLED");
    printf("Code Integrity Check: Test Signing:                         %s\n", status->IsTestSigningEnabled ? "[-] ENABLED (risky)" : "[+] DISABLED (secure)");
    printf("Environment Check: Secure Boot:                             %s\n", status->IsSecureBootEnabled ? "[+] ENABLED" : "[-] DISABLED");
    printf("Driver check and direct coms with TPM driver: TPM Ready:    %s\n", status->IsTpmReady ? "[+] YES" : "[-] NO");
    printf("Kernel API Check: IOMMU Available:                          %s\n", status->IsIommuEnabled ? "[+] YES" : "[-] NO");
    printf("Registry Check: Vulnerable Driver Blocklist:                %s\n", status->IsVulnerableDriverBlocklistEnabled ? "[+] ENABLED" : "[-] DISABLED");
    printf("------------------------------\n");
}

int main()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL bResult;
    TBS_HCONTEXT hTbsContext = NULL;
    TBS_CONTEXT_PARAMS2 contextParams;

#ifndef TBS_CONTEXT_VERSION_2
#define TBS_CONTEXT_VERSION_2 2
#endif

    // Step 1: "Warm-up" the TPM by creating a TBS context.
    // This ensures tpm.sys is loaded if available.
    printf("Attempting to initialize TPM Base Services...\n");
    contextParams.version = TBS_CONTEXT_VERSION_2;
    contextParams.includeTpm20 = 1; // Specify TPM 2.0
    bResult = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hTbsContext);

    if (bResult != TBS_SUCCESS) {
        printf("Warning: Tbsi_Context_Create failed with error 0x%x. TPM may not be available.\n", bResult);

        // We continue anyway, to let the driver make the final determination.
    } else {
        printf("TPM Base Services initialized successfully.\n");
        Tbsip_Context_Close(hTbsContext); // Close the handle, we're done with it.
    }
    printf("\n");

    // Step 2: Open a handle to our driver.
    hDevice = CreateFileW(
        L"\\\\.\\SFEnforcer", // Note: \\.\ maps to \DosDevices
        GENERIC_READ,         // Only request read access since we only read security status
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error: CreateFile failed for SFEnforcer device: %d\n", GetLastError());
        return 1;
    }

    printf("Successfully opened handle to the SFEnforcer device.\n");

    // Step 3: Send the IOCTL to the driver to get the security status.
    SYSTEM_SECURITY_STATUS securityStatus = { 0 };
    DWORD bytesReturned = 0;

    bResult = DeviceIoControl(hDevice, IOCTL_GET_SECURITY_STATUS, NULL, 0, &securityStatus, sizeof(securityStatus), &bytesReturned, NULL);

    if (!bResult) {
        printf("Error: DeviceIoControl failed: %d\n", GetLastError());
    }
    else if (bytesReturned == sizeof(SYSTEM_SECURITY_STATUS)) {
        PrintSecurityStatus(&securityStatus);
        printf("Security Analysis Summary: HVCI=%s, Secure Boot=%s, TPM Ready=%s, DSE=%s, Test Signing=%s, IOMMU=%s, VDB=%s\n",
            securityStatus.IsHvciEnabled ? "ENABLED" : "DISABLED",
            securityStatus.IsSecureBootEnabled ? "ENABLED" : "DISABLED", 
            securityStatus.IsTpmReady ? "YES" : "NO",
            securityStatus.IsDseEnabled ? "ENABLED" : "DISABLED",
            securityStatus.IsTestSigningEnabled ? "ENABLED" : "DISABLED",
            securityStatus.IsIommuEnabled ? "YES" : "NO",
            securityStatus.IsVulnerableDriverBlocklistEnabled ? "ENABLED" : "DISABLED");
    }
    else {
        printf("DeviceIoControl returned an unexpected number of bytes: %d\n", bytesReturned);
    }

    // Clean up
    CloseHandle(hDevice);

    printf("\nSimple security status check complete!\n");
    return 0;
}