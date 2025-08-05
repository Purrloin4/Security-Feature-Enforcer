#pragma once
/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

#include <initguid.h> // Include this once, here, to define the GUIDs.

DEFINE_GUID (GUID_DEVINTERFACE_SFEnforcer,
    0x1053a5a1,0x7b83,0x4244,0x80,0x94,0x04,0xe2,0x59,0x0a,0xd5,0x6c);
// {1053a5a1-7b83-4244-8094-04e2590ad56c}

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#endif
#include <devioctl.h>

// Define the single IOCTL code we need
#define IOCTL_GET_SECURITY_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// System security status structure
typedef struct _SYSTEM_SECURITY_STATUS {
    BOOLEAN IsHvciEnabled;
    BOOLEAN IsSecureBootEnabled;
    BOOLEAN IsTpmReady;
    BOOLEAN IsDseEnabled;
    BOOLEAN IsTestSigningEnabled;
    BOOLEAN IsVulnerableDriverBlocklistEnabled;
    BOOLEAN IsIommuEnabled;
} SYSTEM_SECURITY_STATUS, *PSYSTEM_SECURITY_STATUS;