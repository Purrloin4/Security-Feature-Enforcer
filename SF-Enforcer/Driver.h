/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h> // Include for SDDL constants
#pragma comment(lib, "wdmsec.lib") // Link against the library with the SDDL definitions

#include "public.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_OBJECT_CONTEXT_CLEANUP SFEnforcerEvtDriverContextCleanup;

EXTERN_C_END
