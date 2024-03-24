#include "IOCTLFunctions.h"
#include "Memory.h"
#include "ProcessDump.h"
#include "ModuleDump.h"
#include "UserModeBridge.h"
#include "Utility.h"



NTSTATUS DumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
{
	
	NTSTATUS      status;
	UINT64   bytesIO = 0;
	
	if(ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(DUMP_PROCESS) &&
		ourStack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(DUMP_PROCESS))
	{
		PDUMP_PROCESS request = (PDUMP_PROCESS)Irp->AssociatedIrp.SystemBuffer;


		request->Response = Dump_Process(request->ProcName, request->DumpFolder, request->DumpName);

		
		bytesIO = sizeof(DUMP_PROCESS);
		status = STATUS_SUCCESS;

		
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = bytesIO;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return Irp->IoStatus.Status;
	}

	status = STATUS_INFO_LENGTH_MISMATCH;
	bytesIO = 0;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}







NTSTATUS DumpMod(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
{
	NTSTATUS      status;
	UINT64   bytesIO = 0;
	
	if (ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(DUMP_MODULE) &&
		ourStack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(DUMP_MODULE))
	{

		PDUMP_MODULE request = (PDUMP_MODULE)Irp->AssociatedIrp.SystemBuffer;

		request->Response = Dump_Module(request->DumpFolder, request->DumpName, request->ModuleName);
		

		bytesIO = sizeof(DUMP_MODULE);
		status = STATUS_SUCCESS;


		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = bytesIO;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return Irp->IoStatus.Status;
	}

	status = STATUS_INFO_LENGTH_MISMATCH;
	bytesIO = 0;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}





NTSTATUS Hijack(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
{
	NTSTATUS      status;
	UINT64	 bytesIO = 0;

	if (ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(HIJACK_TOKEN) &&
		ourStack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(HIJACK_TOKEN))
	{

		PHIJACK_TOKEN request = (PHIJACK_TOKEN)Irp->AssociatedIrp.SystemBuffer;


		request->Response = Hijack_Token(request->TargetProc, request->OurProc);

		
		bytesIO = sizeof(HIJACK_TOKEN);
		status = STATUS_SUCCESS;


		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = bytesIO;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return Irp->IoStatus.Status;
	}

	status = STATUS_INFO_LENGTH_MISMATCH;
	bytesIO = 0;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}




//NTSTATUS AdvDumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
//{
//
//	NTSTATUS      status;
//	UINT64   bytesIO = 0;
//
//	if (ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ADV_DUMP_PROCESS))
//	{
//		PADV_DUMP_PROCESS request = (PADV_DUMP_PROCESS)Irp->AssociatedIrp.SystemBuffer;
//
//		RtlInitUnicodeString(&AdvDmpTarget, request->ProcName);
//		RtlInitUnicodeString(&AvdDumpFldr, request->DumpFolder);
//		RtlInitUnicodeString(&AvdDumpName, request->DumpName);
//
//		PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)Advanced_Process_Dump, FALSE);
//
//
//		bytesIO = sizeof(ADV_DUMP_PROCESS);
//		status = STATUS_SUCCESS;
//
//
//		Irp->IoStatus.Status = status;
//		Irp->IoStatus.Information = bytesIO;
//		IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//		return Irp->IoStatus.Status;
//	}
//
//	status = STATUS_INFO_LENGTH_MISMATCH;
//	bytesIO = 0;
//
//	Irp->IoStatus.Status = status;
//	Irp->IoStatus.Information = bytesIO;
//	IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//	return Irp->IoStatus.Status;
//}