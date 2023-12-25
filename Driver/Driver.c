#include "Globals.h"
#include "UserModeBridge.h"
#include "IOCTLFunctions.h"
#include <wdf.h>



DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

///global driver info
UNICODE_STRING deviceName, symLink;
PDEVICE_OBJECT deviceObject;



NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

static NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("[+]UnloadDriver() Function Called\n");
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS status = ZwUnloadDriver(&deviceName);
	if(status == STATUS_SUCCESS) DbgPrint("[+]Operation Successfull\n");
	else	
		DbgPrint("[!]Operation Unsuccessfull\n");
	
	return status;
}

static NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	ULONG													bytesIO = 0;
	NTSTATUS												 status = 1;
	PIO_STACK_LOCATION		  stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	

	switch (controlCode)
	{
	case IOCTL_DUMP_PROCESS:
		status = DumpProc(Irp);
		break;
	case IOCTL_DUMP_MODULE:
		status = DumpMod(Irp);
		break;
	case IOCTL_HIJACK_TOKEN:
		status = Hijack(Irp);
		break;
	case IOCTL_PROC_BASE:
		status = Get_Base_Addr(Irp);
		break;
	case IOCTL_UNLOAD:	
		{status = UnloadDriver(deviceObject->DriverObject);
		bytesIO = 0; }
		break;
	case STATUS_INVALID_PARAMETER:
		{status = STATUS_INVALID_PARAMETER;
		bytesIO = 0;}
		break;
	}

	return status;
}

extern NTSTATUS DriverInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

#ifdef _DEBUG 
	DbgPrint("[+]Driver Intitalization called\n");
#endif
		
	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&deviceName, L"\\Device\\IceBox");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\IceBox");

	if (NT_SUCCESS(status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject)))
	{
		if (!NT_SUCCESS(status = IoCreateSymbolicLink(&symLink, &deviceName)))
		{	
			IoDeleteDevice(deviceObject);
			return status;
		}
	}
	else
	{
		return status;
	}


	for (ULONG_PTR t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl;
	DriverObject->DriverUnload = UnloadDriver;
	
	deviceObject->Flags |= DO_BUFFERED_IO;
	deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

#ifdef _DEBUG 
	if (NT_SUCCESS(status))
	{
		DbgPrint("[+]Driver Intitalization Successfull\n");
	}		
#endif
	
	return status;
}



extern NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
#ifdef _DEBUG 
	DbgPrint("[+]Driver Entry called\n");
#endif
	
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(status = IoCreateDriver(NULL, &DriverInitialize)))
	{
#ifdef _DEBUG 
		DbgPrint("[+]Driver Entry Successfull\n");
#endif
	}
	
	return status;
}

