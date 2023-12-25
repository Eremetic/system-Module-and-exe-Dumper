#include "IOCTLFunctions.h"



NTSTATUS DumpProc(IN PIRP Irp)
{
	
	NTSTATUS status;
	ULONG result = 1;
	DWORD bytesIO = 0;
	PDUMP_PROCESS request = (PDUMP_PROCESS)Irp->AssociatedIrp.SystemBuffer;

	result = Dump_Process(request->ProcName, request->DumpFolder, request->DumpName);


	
	DbgPrint("returning status 0x%I64x\n", result);

	bytesIO = sizeof(result);
	status = STATUS_SUCCESS;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}





NTSTATUS DumpMod(IN PIRP Irp)
{
	NTSTATUS status;
	ULONG result = 1;
	DWORD bytesIO = 0;
	
	PDUMP_MODULE request = (PDUMP_MODULE)Irp->AssociatedIrp.SystemBuffer;

	result = Dump_Module(request->DumpFolder, request->DumpName, request->ModuleName);


	
	DbgPrint("returning status 0x%I64x\n", result);

	bytesIO = sizeof(result);
	status = STATUS_SUCCESS;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}





NTSTATUS Hijack(IN PIRP Irp)
{
	NTSTATUS   status;
	ULONG  result = 1;
	DWORD bytesIO = 0;

	PHIJACK_TOKEN request = (PHIJACK_TOKEN)Irp->AssociatedIrp.SystemBuffer;

	result = Hijack_Token(request->TargetProc, request->OurProc);

	DbgPrint("returning status 0x%I64x\n", result);

	bytesIO = sizeof(result);
	status = STATUS_SUCCESS;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}


NTSTATUS Get_Base_Addr(IN PIRP Irp)
{
#ifdef _DEBUG 
	DbgPrint("[+]Get_Base_Addr() Function Called\n");
#endif
	
	NTSTATUS	         status;
	ULONG		     result = 1;
	DWORD	        bytesIO = 0;
	CLIENT_ID	    cID = { 0 };
	INT64    BaseAddress = 0;
	

	PBASE_ADDR request = (PBASE_ADDR)Irp->AssociatedIrp.SystemBuffer;

	cID = Process_ID(request->TargetProc);
	if (cID.UniqueProcess)
	{
		BaseAddress = (INT64)Process_Query(cID, &result);

	}
	if (result == STATUS_SUCCESS)
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
		DbgPrint("[+]Base Address : %p\n", BaseAddress);
#endif	
		bytesIO = sizeof(BaseAddress);
	}
	else
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
#endif
		bytesIO = 0;
	}

	status = STATUS_SUCCESS;

	Irp->IoStatus.Status              = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}