#include "pch.h"
#include <string>
#include <memory>
#include "..\\SF-Enforcer\\Public.h"

static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static std::string g_lastError;

// Unity plugin export macro
#define UNITY_INTERFACE_EXPORT __declspec(dllexport)

extern "C" {
    UNITY_INTERFACE_EXPORT bool InitializeSecurityDriver();
    UNITY_INTERFACE_EXPORT void CleanupSecurityDriver();
    UNITY_INTERFACE_EXPORT const char* GetLastErrorMessage();
    UNITY_INTERFACE_EXPORT bool GetSecurityStatus(SYSTEM_SECURITY_STATUS* status);
}

HANDLE OpenSecurityDevice()
{
    // Use read-only access since normal users only have read permissions
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\SFEnforcer",
        GENERIC_READ,
        0, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, 
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = ::GetLastError();
        g_lastError = "Failed to open SF-Enforcer device - error code: " + std::to_string(error);
        g_lastError += " (ensure SF-Enforcer driver is installed and running)";
        return INVALID_HANDLE_VALUE;
    }

    g_lastError = "Successfully opened SF-Enforcer device";
    return hDevice;
}

bool InitializeSecurityDriver()
{
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        return true; // Already initialized
    }

    g_hDevice = OpenSecurityDevice();
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        g_lastError = "Security driver initialized successfully";
        return true;
    }
    
    return false;
}

void CleanupSecurityDriver()
{
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
        g_lastError = "Security driver cleaned up";
    }
}

const char* GetLastErrorMessage()
{
    return g_lastError.c_str();
}

bool GetSecurityStatus(SYSTEM_SECURITY_STATUS* status)
{
    if (g_hDevice == INVALID_HANDLE_VALUE) {
        g_lastError = "Driver not initialized - call InitializeSecurityDriver first";
        return false;
    }

    if (!status) {
        g_lastError = "Invalid status buffer";
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        g_hDevice,
        IOCTL_GET_SECURITY_STATUS,
        NULL,
        0,
        status,
        sizeof(SYSTEM_SECURITY_STATUS),
        &bytesReturned,
        NULL
    );

    if (!result) {
        g_lastError = "DeviceIoControl failed with error: " + std::to_string(::GetLastError());
        return false;
    }

    if (bytesReturned != sizeof(SYSTEM_SECURITY_STATUS)) {
        g_lastError = "Unexpected data size returned from driver";
        return false;
    }

    g_lastError = "Security status retrieved successfully";
    return true;
}