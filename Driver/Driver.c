#include "Globals.h"
#include "UserModeBridge.h"
#include "IOCTLFunctions.h"
#include <wdf.h>
#include "Utility.h"


DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)
PDEVICE_OBJECT deviceObject;
UNICODE_STRING deviceName, symLink;


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


NTSTATUS Unload(IN PDRIVER_OBJECT DriverObject)
{
#ifdef _DEBUG 
	DbgPrint("[+]Driver Unload Called\n");
#endif
	
	UNREFERENCED_PARAMETER(DriverObject);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteSymbolicLink(&deviceName);
	IoDeleteDevice(deviceObject);
	return ZwUnloadDriver(&deviceName);
}



static NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	ULONG													bytesIO = 0;
	NTSTATUS												 status = 1;
	PIO_STACK_LOCATION		  stack = IoGetCurrentIrpStackLocation(Irp);


	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DUMP_PROCESS:
		status = DumpProc(stack, Irp);
		break;
	case IOCTL_DUMP_MODULE:
		status = DumpMod(stack, Irp);
		break;
	case IOCTL_HIJACK_TOKEN:
		status = Hijack(stack, Irp);
		break;
	/*case IOCTL_ADV_DUMP_PROCESS:
		status = AdvDumpProc(stack, Irp);
		break;*/
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
	deviceObject->Flags |= DO_BUFFERED_IO;

	for (ULONG_PTR t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControl;
	DriverObject->DriverUnload = &Unload;
	
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
		UNICODE_STRING func = { 0 };
		func.Buffer = L"PsSuspendProcess";
		func.Length = (USHORT)wcslen(func.Buffer) * sizeof(WCHAR);
		func.MaximumLength = func.Length + sizeof(WCHAR);

		suspend_Ptr = MmGetSystemRoutineAddress(&func);

#ifdef _DEBUG 
		DbgPrint("[+]Driver Entry Successfull\n");
#endif
	}
	
	return status;
}

