/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

#pragma once

#include <devioctl.h>

#define IOCTL_GET_SECURITY_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SYSTEM_SECURITY_STATUS {
    BOOLEAN IsHvciEnabled;
    BOOLEAN IsSecureBootEnabled;
    BOOLEAN IsTpmReady;
    BOOLEAN IsDseEnabled;
    BOOLEAN IsTestSigningEnabled;
    BOOLEAN IsVulnerableDriverBlocklistEnabled;
} SYSTEM_SECURITY_STATUS, *PSYSTEM_SECURITY_STATUS;