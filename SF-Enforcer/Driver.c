/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, SFEnforcerEvtDriverContextCleanup)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Register a cleanup callback
    //
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Initializing WDF_OBJECT_ATTRIBUTES");
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = SFEnforcerEvtDriverContextCleanup;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Initializing WDF_DRIVER_CONFIG");
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling WdfDriverCreate");
    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Create a control device object
    //
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling WdfControlDeviceInitAllocate");
    deviceInit = WdfControlDeviceInitAllocate(WdfGetDriver(), &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!deviceInit) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfControlDeviceInitAllocate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Setting device as non-exclusive");
    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling WdfDeviceCreate");
    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDeviceCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Create a device interface
    //
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling WdfDeviceCreateDeviceInterface");
    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_SFEnforcer, NULL);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDeviceCreateDeviceInterface failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Initialize the I/O Package and any Queues
    //
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling SFEnforcerQueueInitialize");
    status = SFEnforcerQueueInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "SFEnforcerQueueInitialize failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Finish initializing the control device
    //
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "Calling WdfControlFinishInitializing");
    WdfControlFinishInitializing(device);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    return status;
}

VOID
SFEnforcerEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
