#include <ntifs.h>
#include "../headers/NULLProtect.h"

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DrvUnloadRoutine;

    UNICODE_STRING DeviceName;
    RtlInitUnicodeString(&DeviceName, L"\\Device\\NullPageProtector");

    PDEVICE_OBJECT DeviceObject = nullptr;
    NTSTATUS Status = IoCreateDevice(DriverObject, NULL, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        KdPrint((DrvName "Error IoCreateDevice (0x%08X)\n", Status));
        return Status;
    }
    UNICODE_STRING symlnk = RTL_CONSTANT_STRING(L"\\??\\NullPageProtector");
    Status = IoCreateSymbolicLink(&symlnk, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        KdPrint((DrvName"Error IoCreateSymbolicLink (0x%08X)\n", Status));
        return Status;
    }

    // Register the process creation notification callback
    Status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(Status)) {
        KdPrint((DrvName "Error PsSetCreateProcessNotifyRoutine (0x%08X)\n", Status));
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    return STATUS_SUCCESS;
}


void DrvUnloadRoutine(PDRIVER_OBJECT DriverObject)
{
    PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
    UNICODE_STRING symlnk = RTL_CONSTANT_STRING(L"\\??\\NullPageProtectorDrv");
    IoDeleteSymbolicLink(&symlnk);
    IoDeleteDevice(DriverObject->DeviceObject);
}