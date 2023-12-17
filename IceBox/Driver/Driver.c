#include "Globals.h"
#include "UserModeBridge.h"
#include "ModuleDump.h"
#include "ProcessDump.h"
#include <wdf.h>
#include "TokenHijack.h"

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

///global driver info
UNICODE_STRING deviceName, symLink;
PDEVICE_OBJECT deviceObject;



NTSTATUS UnsupportedDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CreateDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

static NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[+]UnloadDriver() Function Called.\n");
	NTSTATUS status;

	status = IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	return status;
}

static NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = 0;
	ULONG bytesIO = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IOCTL_DUMP_PROCESS)
	{
		PDUMP_PROCESS request = (PDUMP_PROCESS)Irp->AssociatedIrp.SystemBuffer;

		request->Response = Dump_Process(request->pPid, request->DumpFolder, request->DumpName);
		DbgPrint("returning status 0x%I64x\n", request->Response);

		bytesIO = sizeof(PDUMP_PROCESS);
		status = STATUS_SUCCESS;
	}
	else if (controlCode == IOCTL_DUMP_MODULE)
	{
			PDUMP_MODULE request = (PDUMP_MODULE)Irp->AssociatedIrp.SystemBuffer;
			
			request->Response = Dump_Module(request->DumpFolder, request->DumpName, request->ModuleName);
			DbgPrint("returning status 0x%I64x\n", request->Response);
				
			bytesIO = sizeof(PDUMP_MODULE);
			status = STATUS_SUCCESS;
	}
	else if (controlCode == IOCTL_HIJACK_TOKEN)
	{
		PHIJACK_TOKEN request = (PHIJACK_TOKEN)Irp->AssociatedIrp.SystemBuffer;

		request->Response = Hijack_Token(request->PID);
		DbgPrint("returning status 0x%I64x\n", request->Response);

		bytesIO = sizeof(PHIJACK_TOKEN);
		status = STATUS_SUCCESS;
	}
	else if (controlCode == IO_UNLOAD_DRIVER)
	{
		status = UnloadDriver(deviceObject->DriverObject);
		bytesIO = 0;
	}
	else
	{
		status = STATUS_INVALID_PARAMETER;
		bytesIO = 0;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

extern NTSTATUS DriverInitialize(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

#ifdef _DEBUG 
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[+]Driver Intitalization called\n");
#endif
		
	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&deviceName, L"\\Device\\IceBox");
	RtlInitUnicodeString(&symLink, L"\\DosDevices\\IceBox");

	if (NT_SUCCESS(status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject)))
	{
		if (!NT_SUCCESS(status = IoCreateSymbolicLink(&symLink, &deviceName)))
		{
#ifdef _DEBUG 
			DbgPrint("[!]Failed To Create SymbolicLink\n");
#endif	
			IoDeleteDevice(deviceObject);
			return status;
		}
	}
	else
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Create Device\n");
#endif
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
		DbgPrint("[+]Driver Entry Successfulll\n");
#endif
	}
	
	return status;
}

