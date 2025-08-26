/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions for manual mapped version.
    This version is designed to work with kdmapper and avoids WDF dependencies.

Environment:

    Kernel-mode Driver Framework

--*/

#ifndef _DRIVER_H_
#define _DRIVER_H_

#include <ntddk.h>

// Tutorial pattern: Function prototypes without attributes
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Global variables like tutorial
extern UNICODE_STRING dev, dos;
extern PDEVICE_OBJECT pDeviceObject;

#endif