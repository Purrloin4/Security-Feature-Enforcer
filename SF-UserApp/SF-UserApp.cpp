#include <initguid.h>
#include <Windows.h>
#include <stdio.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <regstr.h>
#include "..\\SF-Enforcer\\Public.h"

#pragma comment (lib, "Setupapi.lib")

int main()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL bResult;

    // Directly open the device using its symbolic link name.
    // The name \\.\ is the user-mode prefix for \\DosDevices
    hDevice = CreateFileW(
    L"\\\\.\\SFEnforcer",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );

        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Error: CreateFileW failed with error code: %d\n", GetLastError());
            printf("Is the driver running?\n");
            return 1;
        }

        printf("Successfully opened handle to the device.\n\n");

    // Now, send the IOCTL to the driver
    SYSTEM_SECURITY_STATUS securityStatus = { 0 };
    DWORD bytesReturned = 0;

	bResult = DeviceIoControl(hDevice, IOCTL_GET_SECURITY_STATUS, NULL, 0, &securityStatus, sizeof(securityStatus), &bytesReturned, NULL); // Send reqsuest to driver

    if (!bResult) {
        printf("Error: DeviceIoControl failed: %d\n", GetLastError());
    }
    else if (bytesReturned == sizeof(SYSTEM_SECURITY_STATUS)) {
        printf("--- System Security Status ---\n");
        printf("Memory Integrity (HVCI): %s\n", securityStatus.IsHvciEnabled ? "Enabled" : "Disabled");
        printf("Secure Boot:             %s\n", securityStatus.IsSecureBootEnabled ? "Enabled" : "Disabled");
        printf("TPM Ready:               %s\n", securityStatus.IsTpmReady ? "Yes" : "No");
        printf("------------------------------\n");
    }
    else {
        printf("DeviceIoControl returned an unexpected number of bytes: %d\n", bytesReturned);
    }

    // Clean up
    CloseHandle(hDevice);

    return 0;
}