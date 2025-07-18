#include <Windows.h>
#include <stdio.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <regstr.h>
#include "Public.h"

#pragma comment (lib, "Setupapi.lib")

int main()
{
    HDEVINFO hDevInfo;
    SP_DEVICE_INTERFACE_DATA devInterfaceData;
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W pDetailData = NULL;
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DWORD requiredSize = 0;
    BOOL bResult;

    // Get the device information set for our interface GUID
    hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_SFEnforcer, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        printf("Error: SetupDiGetClassDevs failed: %d\n", GetLastError());
        return 1;
    }

    devInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    // Enumerate the device interfaces
    bResult = SetupDiEnumDeviceInterfaces(hDevInfo, 0, &GUID_DEVINTERFACE_SFEnforcer, 0, &devInterfaceData);
    if (!bResult) {
        printf("Error: SetupDiEnumDeviceInterfaces failed: %d\n", GetLastError());
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return 1;
    }

    // Get the required size for the detail data
    SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, NULL, 0, &requiredSize, NULL);

    // Allocate memory for the detail data
    pDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(requiredSize);
    if (pDetailData == NULL) {
        printf("Error: Failed to allocate memory for device detail data.\n");
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return 1;
    }
    pDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    // Get the device interface detail data
    bResult = SetupDiGetDeviceInterfaceDetailW(hDevInfo, &devInterfaceData, pDetailData, requiredSize, &requiredSize, NULL);
    if (!bResult) {
        printf("Error: SetupDiGetDeviceInterfaceDetailW failed: %d\n", GetLastError());
        free(pDetailData);
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return 1;
    }

    // Open a handle to the device
    hDevice = CreateFileW(pDetailData->DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error: CreateFile failed: %d\n", GetLastError());
        free(pDetailData);
        SetupDiDestroyDeviceInfoList(hDevInfo);
        return 1;
    }

    printf("Successfully opened handle to the device.\n");
    printf("Device Path: %ws\n\n", pDetailData->DevicePath);

    // Now, send the IOCTL to the driver
    SYSTEM_SECURITY_STATUS securityStatus = { 0 };
    DWORD bytesReturned = 0;

    bResult = DeviceIoControl(hDevice, IOCTL_GET_SECURITY_STATUS, NULL, 0, &securityStatus, sizeof(securityStatus), &bytesReturned, NULL);

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
    free(pDetailData);
    SetupDiDestroyDeviceInfoList(hDevInfo);
    CloseHandle(hDevice);

    return 0;
}