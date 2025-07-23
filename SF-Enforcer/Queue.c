/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "queue.tmh"
#include <wdmsec.h> // Required for SDDL_DEVOBJ_SYS_ALL_ADM_ALL
#include <ntstrsafe.h> // For RtlStringCbPrintfA
#pragma comment(lib, "Wdmsec.lib") // Link against Wdmsec.lib

// Manually define structures and functions to avoid header conflicts with ntifs.h
typedef ULONG SYSTEM_INFORMATION_CLASS;

// Define the constants for SYSTEM_INFORMATION_CLASS to check for code integrity information source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/codeintegrity.htm

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation 0x67
#endif

#ifndef CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED
#define CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED 0x400
#endif

#ifndef SERVICE_DISABLED
#define SERVICE_DISABLED 4
#endif

typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION {
    ULONG  Length;
    ULONG  CodeIntegrityOptions;
} SYSTEM_CODE_INTEGRITY_INFORMATION, * PSYSTEM_CODE_INTEGRITY_INFORMATION;

// ZwQuerySystemInformation is the undocumented kernel function of NtQuerySystemInformation source: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemEnvironmentValueEx(
    _In_ PUNICODE_STRING VariableName,
    _In_ LPGUID VendorGuid,
    _Out_writes_bytes_to_opt_(*ValueLength, *ValueLength) PVOID Value,
    _Inout_ PULONG ValueLength,
    _Out_opt_ PULONG Attributes
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, SFEnforcerQueueInitialize)
#endif

VOID GetSecurityStatus(_Out_ PSYSTEM_SECURITY_STATUS Status);

NTSTATUS
SFEnforcerQueueInitialize(
    _In_ WDFDEVICE Device
    )
/*++

Routine Description:

     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    VOID

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
         &queueConfig,
        WdfIoQueueDispatchParallel
        );

    queueConfig.EvtIoDeviceControl = SFEnforcerEvtIoDeviceControl;
    queueConfig.EvtIoStop = SFEnforcerEvtIoStop;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &queue
                 );

    if(!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

// This helper function performs the actual security checks.
VOID GetSecurityStatus(_Out_ PSYSTEM_SECURITY_STATUS Status)
{
    RtlZeroMemory(Status, sizeof(SYSTEM_SECURITY_STATUS));
    NTSTATUS ntStatus;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES objAttr;

    // 1. Check for HVCI (Memory Integrity)
    SYSTEM_CODE_INTEGRITY_INFORMATION sci_info = { 0 };
    sci_info.Length = sizeof(sci_info);
    ntStatus = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &sci_info, sizeof(sci_info), NULL);
    if (NT_SUCCESS(ntStatus)) {
        if (sci_info.CodeIntegrityOptions & CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED) {
            Status->IsHvciEnabled = TRUE;
        }
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "HVCI Check: Enabled = %d", Status->IsHvciEnabled);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "HVCI Check: ZwQuerySystemInformation failed %!STATUS!", ntStatus);
    }

    // 2. Check for Secure Boot
    UNICODE_STRING varName = RTL_CONSTANT_STRING(L"SecureBoot");
    UCHAR secureBootValue = 0;
    // EFI_GLOBAL_VARIABLE is a GUID used for SecureBoot UEFI variable
    // {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
    static GUID EFI_GLOBAL_VARIABLE = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } };
    ULONG valueLength = sizeof(secureBootValue);
    ntStatus = ExGetFirmwareEnvironmentVariable(&varName, &EFI_GLOBAL_VARIABLE, &secureBootValue, &valueLength, NULL);

    if (NT_SUCCESS(ntStatus)) {
        if (secureBootValue == 1) {
            Status->IsSecureBootEnabled = TRUE;
        }
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Secure Boot Check: Enabled = %d", Status->IsSecureBootEnabled);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "Secure Boot Check: ExGetFirmwareEnvironmentVariable failed %!STATUS!", ntStatus);
    }

    // 3. Check for TPM readiness using service enumeration.
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Starting registry query for service enumeration.");
    
    UNICODE_STRING tpmEnumKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\Enum");
    
    InitializeObjectAttributes(&objAttr, &tpmEnumKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ntStatus = ZwOpenKey(&hKey, KEY_READ, &objAttr);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: ZwOpenKey on TPM\\Enum returned %!STATUS!", ntStatus);

    if (NT_SUCCESS(ntStatus)) {
        UNICODE_STRING enumZeroValueName = RTL_CONSTANT_STRING(L"0");
        UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 256]; // Allow for longer strings
        PKEY_VALUE_PARTIAL_INFORMATION pValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        ULONG resultLength = 0;

        ntStatus = ZwQueryValueKey(hKey, &enumZeroValueName, KeyValuePartialInformation, pValueInfo, sizeof(buffer), &resultLength);
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: ZwQueryValueKey on Enum\\0 returned %!STATUS!", ntStatus);

        if (NT_SUCCESS(ntStatus) && (pValueInfo->Type == REG_SZ || pValueInfo->Type == REG_EXPAND_SZ)) {
            // Check if we have actual data and it's not empty
            if (pValueInfo->DataLength > sizeof(WCHAR)) {
                // Log the enum value for debugging (just the length, not the actual string to avoid complexity)
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Enum\\0 value found (Length: %u)", pValueInfo->DataLength);
                
                // If there's a meaningful value in Enum\0, TPM is enumerated and ready
                Status->IsTpmReady = TRUE;
            } else {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Enum\\0 value is empty or too short");
            }
        } else {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Enum\\0 value not found or wrong type");
        }
        // Also check the Count value to see how many TPM devices are enumerated
        if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_READ, &objAttr))) {
            UNICODE_STRING countValueName = RTL_CONSTANT_STRING(L"Count");
            UCHAR countBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
            PKEY_VALUE_PARTIAL_INFORMATION pCountInfo = (PKEY_VALUE_PARTIAL_INFORMATION)countBuffer;
            ULONG countResultLength = 0;

            ntStatus = ZwQueryValueKey(hKey, &countValueName, KeyValuePartialInformation, pCountInfo, sizeof(countBuffer), &countResultLength);
            if (NT_SUCCESS(ntStatus) && pCountInfo->Type == REG_DWORD) {
                ULONG tpmCount = *((PULONG)pCountInfo->Data);
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Enum\\Count value is %u", tpmCount);
                
                // If count is greater than 0, we have enumerated TPM devices
                if (tpmCount > 0) {
                    Status->IsTpmReady = TRUE;
                }
            } else {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Enum\\Count query returned %!STATUS!", ntStatus);
            }
            ZwClose(hKey);
            hKey = NULL;
        }
    } else {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: TPM\\Enum key not accessible, TPM likely not present");
    }

    //// 4. For comparison, also check EkNoFetch (known to be unreliable in VMs)
    //PVOID pValueBuffer = NULL;
    //UNICODE_STRING endorsementKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement");
    //InitializeObjectAttributes(&objAttr, &endorsementKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    //ntStatus = ZwOpenKey(&hKey, KEY_READ, &objAttr);
    //if (NT_SUCCESS(ntStatus)) {
    //    UNICODE_STRING ekNoFetchValueName = RTL_CONSTANT_STRING(L"EkNoFetch");
    //    UCHAR ekBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    //    PKEY_VALUE_PARTIAL_INFORMATION pEkInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ekBuffer;
    //    ULONG ekResultLength = 0;

    //    ntStatus = ZwQueryValueKey(hKey, &ekNoFetchValueName, KeyValuePartialInformation, pEkInfo, sizeof(ekBuffer), &ekResultLength);
    //    if (NT_SUCCESS(ntStatus) && pEkInfo->Type == REG_DWORD) {
    //        ULONG ekNoFetchValue = *((PULONG)pEkInfo->Data);
    //        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: EkNoFetch value is %u (for comparison)", ekNoFetchValue);
    //    }
    //    ZwClose(hKey);
    //    hKey = NULL;
    //}

    //// 5. For debugging, query and log the UEFI variables without changing the status.
    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: Investigating UEFI variables.");
    //static GUID ODUID_NAMESPACE_GUID = { 0xeaec226f, 0xc9a3, 0x477a, { 0xa8, 0x26, 0xdd, 0xc7, 0x16, 0xcd, 0xc0, 0xe3 } };
    //ULONG attributes = 0;
    //valueLength = 0;

    //// Check for OfflineUniqueIDEKPub
    //UNICODE_STRING oduidEkPubVarName = RTL_CONSTANT_STRING(L"OfflineUniqueIDEKPub");
    //ntStatus = ZwQuerySystemEnvironmentValueEx(&oduidEkPubVarName, &ODUID_NAMESPACE_GUID, NULL, &valueLength, &attributes);
    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: Query for OfflineUniqueIDEKPub size returned %!STATUS!", ntStatus);
    //if (ntStatus == STATUS_BUFFER_TOO_SMALL && valueLength > 0) {
    //    pValueBuffer = ExAllocatePool2(POOL_FLAG_PAGED, valueLength, 'kpeT');
    //    if (pValueBuffer) {
    //        ntStatus = ZwQuerySystemEnvironmentValueEx(&oduidEkPubVarName, &ODUID_NAMESPACE_GUID, pValueBuffer, &valueLength, &attributes);
    //        if (NT_SUCCESS(ntStatus)) {
    //            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: OfflineUniqueIDEKPub Value (Length: %u):", valueLength);
    //            UCHAR* data = (UCHAR*)pValueBuffer;
    //            ULONG i;
    //            // Simple hex dump without sprintf - just log the first 32 bytes for debugging
    //            for (i = 0; i < valueLength && i < 32; i += 4) {
    //                if (i + 3 < valueLength) {
    //                    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Offset %04X: %02X %02X %02X %02X", 
    //                        i, data[i], data[i+1], data[i+2], data[i+3]);
    //                } else {
    //                    // Handle remaining bytes
    //                    if (i < valueLength) {
    //                        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Offset %04X: %02X", i, data[i]);
    //                    }
    //                    if (i + 1 < valueLength) {
    //                        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Offset %04X: %02X %02X", i, data[i], data[i+1]);
    //                    }
    //                    if (i + 2 < valueLength) {
    //                        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Offset %04X: %02X %02X %02X", i, data[i], data[i+1], data[i+2]);
    //                    }
    //                }
    //            }
    //        }
    //        ExFreePoolWithTag(pValueBuffer, 'kpeT');
    //        pValueBuffer = NULL;
    //    }
    //}

    //// Check for OfflineUniqueIDRandomSeed
    //valueLength = 0;
    //UNICODE_STRING oduidSeedVarName = RTL_CONSTANT_STRING(L"OfflineUniqueIDRandomSeed");
    //ntStatus = ZwQuerySystemEnvironmentValueEx(&oduidSeedVarName, &ODUID_NAMESPACE_GUID, NULL, &valueLength, &attributes);
    //TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: Query for OfflineUniqueIDRandomSeed size returned %!STATUS!", ntStatus);
    //if (ntStatus == STATUS_BUFFER_TOO_SMALL && valueLength > 0) {
    //    pValueBuffer = ExAllocatePool2(POOL_FLAG_PAGED, valueLength, 'kpeT');
    //    if (pValueBuffer) {
    //        ntStatus = ZwQuerySystemEnvironmentValueEx(&oduidSeedVarName, &ODUID_NAMESPACE_GUID, pValueBuffer, &valueLength, &attributes);
    //        if (NT_SUCCESS(ntStatus)) {
    //            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Debug: OfflineUniqueIDRandomSeed Value (Length: %u):", valueLength);
    //            UCHAR* data = (UCHAR*)pValueBuffer;
    //            ULONG i;
    //            for (i = 0; i < valueLength && i < 32; i++) {
    //                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Byte %02u: %02X", i, data[i]);
    //            }
    //        }
    //        ExFreePoolWithTag(pValueBuffer, 'kpeT');
    //        pValueBuffer = NULL;
    //    }
    //}

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Final Security Status - HVCI: %d, Secure Boot: %d, TPM Ready: %d",
        Status->IsHvciEnabled, Status->IsSecureBootEnabled, Status->IsTpmReady);
}

VOID
SFEnforcerEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
        Queue, Request, (int)OutputBufferLength, (int)InputBufferLength, IoControlCode);

    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;

    switch (IoControlCode) {
    case IOCTL_GET_SECURITY_STATUS:
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Received IOCTL_GET_SECURITY_STATUS");

        if (OutputBufferLength < sizeof(SYSTEM_SECURITY_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            PSYSTEM_SECURITY_STATUS outBuffer;
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(SYSTEM_SECURITY_STATUS), &outBuffer, NULL);
            if (NT_SUCCESS(status)) {
                GetSecurityStatus(outBuffer);
                bytesReturned = sizeof(SYSTEM_SECURITY_STATUS);
            }
            else {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfRequestRetrieveOutputBuffer failed %!STATUS!", status);
            }
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

VOID
SFEnforcerEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION, 
                TRACE_QUEUE, 
                "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d", 
                Queue, Request, ActionFlags);

    //
    // In most cases, the EvtIoStop callback function completes, cancels, or postpones
    // further processing of the I/O request.
    //
    // Typically, the driver uses the following rules:
    //
    // - If the driver owns the I/O request, it calls WdfRequestUnmarkCancelable
    //   (if the request is cancelable) and either calls WdfRequestStopAcknowledge
    //   with a Requeue value of TRUE, or it calls WdfRequestComplete with a
    //   completion status value of STATUS_SUCCESS or STATUS_CANCELLED.
    //
    //   Before it can call these methods safely, the driver must make sure that
    //   its implementation of EvtIoStop has exclusive access to the request.
    //
    //   In order to do that, the driver must synchronize access to the request
    //   to prevent other threads from manipulating the request concurrently.
    //   The synchronization method you choose will depend on your driver's design.
    //
    //   For example, if the request is held in a shared context, the EvtIoStop callback
    //   might acquire an internal driver lock, take the request from the shared context,
    //   and then release the lock. At this point, the EvtIoStop callback owns the request
    //   and can safely complete or requeue the request.
    //
    // - If the driver has forwarded the I/O request to an I/O target, it either calls
    //   WdfRequestCancelSentRequest to attempt to cancel the request, or it postpones
    //   further processing of the request and calls WdfRequestStopAcknowledge with
    //   a Requeue value of FALSE.
    //
    // A driver might choose to take no action in EvtIoStop for requests that are
    // guaranteed to complete in a small amount of time.
    //
    // In this case, the framework waits until the specified request is complete
    // before moving the device (or system) to a lower power state or removing the device.
    // Potentially, this inaction can prevent a system from entering its hibernation state
    // or another low system power state. In extreme cases, it can cause the system
    // to crash with bugcheck code 9F.
    //

    return;
}
