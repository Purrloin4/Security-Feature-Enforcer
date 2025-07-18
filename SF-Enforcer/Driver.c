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
    // Register a cleanup callback so that we can call WPP_CLEANUP when
    // the framework driver object is deleted during driver unload.
    //
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = SFEnforcerEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config,
                           WDF_NO_EVENT_CALLBACK // This is no longer a PnP driver
                           );

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &attributes,
                             &config,
                             WDF_NO_HANDLE
                             );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Create a control device object. This is the correct model for a software-only
    // driver that provides an IOCTL interface.
    //
    deviceInit = WdfControlDeviceInitAllocate(
        WdfGetDriver(),
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL // Allow system and admin access
    );

    if (!deviceInit) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfControlDeviceInitAllocate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Set exclusive to FALSE so that multiple applications can talk to the driver
    // at the same time.
    //
    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    // We are not using a context for the device object, so we can use WDF_NO_OBJECT_ATTRIBUTES.
    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDeviceCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Create a device interface so that applications can find and talk to us.
    //
    status = WdfDeviceCreateDeviceInterface(
        device,
        &GUID_DEVINTERFACE_SFEnforcer,
        NULL // ReferenceString
    );
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDeviceCreateDeviceInterface failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Initialize the I/O Package and any Queues
    //
    status = SFEnforcerQueueInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "SFEnforcerQueueInitialize failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Tell the framework that this device is finished initializing.
    // This is required for control devices.
    //
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
