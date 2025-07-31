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

#ifndef CODE_INTEGRITY_OPTIONS_ENABLED
#define CODE_INTEGRITY_OPTIONS_ENABLED 0x01  // DSE - we want this ENABLED
#endif

#ifndef CODE_INTEGRITY_OPTIONS_TESTSIGN
#define CODE_INTEGRITY_OPTIONS_TESTSIGN 0x02  // Test Signing - we want this DISABLED
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

    // 1. Check Code Integrity Information (HVCI, DSE, Test Signing)
    // All these checks use the same ZwQuerySystemInformation call
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Code Integrity Check: Starting comprehensive analysis.");
    
    SYSTEM_CODE_INTEGRITY_INFORMATION sci_info = { 0 };
    sci_info.Length = sizeof(sci_info);
    ntStatus = ZwQuerySystemInformation(SystemCodeIntegrityInformation, &sci_info, sizeof(sci_info), NULL);
    
    if (NT_SUCCESS(ntStatus)) {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Code Integrity Check: CodeIntegrityOptions = 0x%X", sci_info.CodeIntegrityOptions);
        
        // Check HVCI (Memory Integrity) - flag 0x400
        if (sci_info.CodeIntegrityOptions & CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED) {
            Status->IsHvciEnabled = TRUE;
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "HVCI Check: CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED (0x400) is set - HVCI is active");
        } else {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "HVCI Check: CODE_INTEGRITY_OPTIONS_HVCI_KMCI_ENABLED (0x400) is NOT set - HVCI is inactive");
        }
        
        // Check DSE (Driver Signature Enforcement) - flag 0x01
        if (sci_info.CodeIntegrityOptions & CODE_INTEGRITY_OPTIONS_ENABLED) {
            Status->IsDseEnabled = TRUE;
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "DSE Check: CODE_INTEGRITY_OPTIONS_ENABLED (0x01) is set - DSE is active");
        } else {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "DSE Check: CODE_INTEGRITY_OPTIONS_ENABLED (0x01) is NOT set - DSE is inactive");
        }
        
        // Check Test Signing - flag 0x02
        if (sci_info.CodeIntegrityOptions & CODE_INTEGRITY_OPTIONS_TESTSIGN) {
            Status->IsTestSigningEnabled = TRUE;
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "Test Signing Check: CODE_INTEGRITY_OPTIONS_TESTSIGN (0x02) is set - Test signing is enabled (security risk)");
        } else {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Test Signing Check: CODE_INTEGRITY_OPTIONS_TESTSIGN (0x02) is NOT set - Test signing is disabled (good for security)");
        }
        
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Code Integrity Summary: HVCI=%d, DSE=%d, TestSigning=%d", 
            Status->IsHvciEnabled, Status->IsDseEnabled, Status->IsTestSigningEnabled);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "Code Integrity Check: ZwQuerySystemInformation failed %!STATUS!", ntStatus);
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

    // 3. Check for TPM readiness using DOS device path (PowerShell method)
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Starting DOS device path method (PowerShell Get-Tpm equivalent).");
    
    // Try DOS device path \\??\TPM - this is exactly what PowerShell Get-Tpm uses
    UNICODE_STRING tpmDosDeviceName = RTL_CONSTANT_STRING(L"\\??\\TPM");
    HANDLE hTpmDosDevice = NULL;
    OBJECT_ATTRIBUTES tpmDosObjAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    
    InitializeObjectAttributes(&tpmDosObjAttr, &tpmDosDeviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ntStatus = ZwOpenFile(&hTpmDosDevice, GENERIC_READ, &tpmDosObjAttr, &ioStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
    
    if (NT_SUCCESS(ntStatus)) {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: SUCCESS - DOS device path \\??\\TPM accessible (PowerShell method)");
        
        // Try the exact IOCTL that PowerShell uses (0x22BC0C) for additional verification
        // This is a TBS command submission IOCTL for TPM presence check
        UCHAR tpmTestCommand[12] = { // TPM2_GetCapability for presence
            0x80, 0x01,             // TPM_ST_NO_SESSIONS (tag = 0x8001)
            0x00, 0x00, 0x00, 0x0C, // Command size = 12 bytes
            0x00, 0x00, 0x01, 0x43, // TPM_CC_GetCapability = 0x143
            0x00, 0x00,             // capability = TPM_CAP_FIRST (0x00)
                };
        UCHAR tpmResponse[1024] = { 0 };
        IO_STATUS_BLOCK tpmIoStatus = { 0 };
        
        ntStatus = ZwDeviceIoControlFile(hTpmDosDevice, NULL, NULL, NULL, &tpmIoStatus, 
                                       0x22BC0C, // Exact IOCTL from API monitoring PowerShell Get-Tpm
                                       tpmTestCommand, sizeof(tpmTestCommand),
                                       tpmResponse, sizeof(tpmResponse));
        
        if (NT_SUCCESS(ntStatus) || ntStatus == STATUS_PENDING) {
            Status->IsTpmReady = TRUE;
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: TBS IOCTL 0x22BC0C successful - TPM is responding to commands");
        } else {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: TBS IOCTL 0x22BC0C failed %!STATUS! - but device path accessible", ntStatus);
        }
        
        ZwClose(hTpmDosDevice);
    } else {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: DOS device path \\??\\TPM failed %!STATUS! - TPM not available", ntStatus);
    }
    
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "TPM Check: Final TPM Ready status = %s", Status->IsTpmReady ? "YES" : "NO");

    // 4. Check for IOMMU availability and functionality using IoGetIommuInterfaceEx
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: Starting IOMMU functionality test using V1 interface.");
    
    DMA_IOMMU_INTERFACE_EX iommuInterface;
    RtlZeroMemory(&iommuInterface, sizeof(iommuInterface));

    ntStatus = IoGetIommuInterfaceEx(1, 0ULL, &iommuInterface);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: IoGetIommuInterfaceEx returned status: %!STATUS! (0x%08X)", ntStatus, ntStatus);

    if (NT_SUCCESS(ntStatus)) {
        if (iommuInterface.Version >= 1) {            
            if (iommuInterface.V1.CreateDomain != NULL && iommuInterface.V1.DeleteDomain != NULL) 
            {                
                PIOMMU_DMA_DOMAIN testDomain = NULL;
                __try {
                    ntStatus = iommuInterface.V1.CreateDomain(FALSE, &testDomain);
                    
                    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: CreateDomain test returned status: %!STATUS! (0x%08X)", ntStatus, ntStatus);
                    
                    if (NT_SUCCESS(ntStatus) && testDomain != NULL) {
                        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: SUCCESS - Domain created successfully! IOMMU is FUNCTIONAL!");
                        Status->IsIommuEnabled = TRUE;
                        
                        // Clean up the test domain immediately
                        __try {
                            NTSTATUS deleteStatus = iommuInterface.V1.DeleteDomain(testDomain);
                            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: Test domain cleanup - DeleteDomain returned %!STATUS!", deleteStatus);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "IOMMU Check: Exception during domain cleanup (0x%08X)", GetExceptionCode());
                        }
                    } else {
                            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: Domain creation failed with status 0x%08X", ntStatus);
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER) {
                    TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "IOMMU Check: Exception during domain creation test (0x%08X)", GetExceptionCode());
                    
                }
            } else {
                TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "IOMMU Check: CreateDomain or DeleteDomain function pointers are NULL");
            }
        } else {
            TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "IOMMU Check: Interface version (%u) is less than 1 - V1 functions not available", iommuInterface.Version);
        }
        
    } else {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "IOMMU Check: Failed to obtain IOMMU interface - %!STATUS!", ntStatus);
    }
    
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "IOMMU Check: Final IOMMU functionality status = %s", 
        Status->IsIommuEnabled ? "FUNCTIONAL" : "NOT FUNCTIONAL");


    // 5. Check for Vulnerable Driver Blocklist via registry
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: Starting registry query.");

    UNICODE_STRING vdbKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config");
    InitializeObjectAttributes(&objAttr, &vdbKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ntStatus = ZwOpenKey(&hKey, KEY_READ, &objAttr);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: ZwOpenKey on CI\\Config returned %!STATUS!", ntStatus);

    if (NT_SUCCESS(ntStatus)) {
        UNICODE_STRING vdbValueName = RTL_CONSTANT_STRING(L"VulnerableDriverBlocklistEnable");
        UCHAR vdbBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION pVdbInfo = (PKEY_VALUE_PARTIAL_INFORMATION)vdbBuffer;
        ULONG vdbResultLength = 0;

        ntStatus = ZwQueryValueKey(hKey, &vdbValueName, KeyValuePartialInformation, pVdbInfo, sizeof(vdbBuffer), &vdbResultLength);
        if (NT_SUCCESS(ntStatus) && pVdbInfo->Type == REG_DWORD) {
            ULONG vdbValue = *((PULONG)pVdbInfo->Data);
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: VulnerableDriverBlocklistEnable = %u", vdbValue);
            if (vdbValue == 1) {
                Status->IsVulnerableDriverBlocklistEnabled = TRUE;
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: Registry value shows blocklist is ENABLED");
            }
            else {
                TraceEvents(TRACE_LEVEL_WARNING, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: Registry value shows blocklist is DISABLED");
            }
        }
        else {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: VulnerableDriverBlocklistEnable registry value not found");
        }
        ZwClose(hKey);
        hKey = NULL;
    }
    else {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Vulnerable Driver Blocklist Check: CI\\Config key not accessible");
    }
    
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Security Analysis Summary:");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  HVCI (Memory Integrity):     %s", Status->IsHvciEnabled ? "ENABLED" : "DISABLED");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  DSE (Driver Sig. Enf.):      %s", Status->IsDseEnabled ? "ENABLED" : "DISABLED");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  Test Signing:                %s", Status->IsTestSigningEnabled ? "ENABLED (risky)" : "DISABLED (secure)");
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  Secure Boot:                 %s", Status->IsSecureBootEnabled ? "ENABLED" : "DISABLED");
	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  TPM Ready:                   %s", Status->IsTpmReady ? "YES" : "NO");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  IOMMU Functional:            %s", Status->IsIommuEnabled ? "YES" : "NO");
    if (Status->IsIommuEnabled) {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  IOMMU Active Protection:     %s", Status->IsHvciEnabled ? "YES (via HVCI)" : "NO (HVCI disabled)");
    }
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "  Vulnerable Driver Blocklist: %s", Status->IsVulnerableDriverBlocklistEnabled ? "ENABLED (secure)" : "DISABLED (risky)");
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "Final Security Status - HVCI: %d, Secure Boot: %d, TPM Ready: %d, DSE: %d, Test Signing: %d, IOMMU Functional: %d, Vulnerable Driver Blocklist: %d",
        Status->IsHvciEnabled, Status->IsSecureBootEnabled, Status->IsTpmReady, Status->IsDseEnabled, Status->IsTestSigningEnabled, Status->IsIommuEnabled, Status->IsVulnerableDriverBlocklistEnabled);
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
