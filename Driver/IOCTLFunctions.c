#include "IOCTLFunctions.h"



NTSTATUS DumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
{
	
	NTSTATUS      status;
	UINT64   bytesIO = 0;
	
	if(ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(DUMP_PROCESS) &&
		ourStack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(DUMP_PROCESS))
	{
		PDUMP_PROCESS request = (PDUMP_PROCESS)Irp->AssociatedIrp.SystemBuffer;


		request->Response = Dump_Process(request->ProcName, request->DumpFolder, request->DumpName);

		DbgPrint("returning status 0x%I64x\n", request->Response);
		
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

		DbgPrint("returning status 0x%I64x\n", request->Response);
		
		
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

		DbgPrint("returning status 0x%I64x\n", request->Response);

		
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


NTSTATUS Get_Base_Addr(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp)
{
#ifdef _DEBUG 
	DbgPrint("[+]Get_Base_Addr() Function Called\n");
#endif
	
	NTSTATUS	         status;
	ULONG		     result = 1;
	DWORD	        bytesIO = 0;
	CLIENT_ID	    cID = { 0 };
	
	if (ourStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(BASE_ADDR) &&
		ourStack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(BASE_ADDR))
	{

		PBASE_ADDR request = (PBASE_ADDR)Irp->AssociatedIrp.SystemBuffer;


		cID = Process_ID(request->TargetProc);
		if (cID.UniqueProcess)
		{
			request->BaseAddr = Process_Query(cID, &result);

		}
		if (result == STATUS_SUCCESS)
		{
#ifdef _DEBUG 
			DbgPrint("[+]Operation Successfull\n");
			DbgPrint("[+]Base Address : %p\n", request->BaseAddr);
#endif	

			bytesIO = sizeof(BASE_ADDR);
		}
		else
		{
#ifdef _DEBUG 
			DbgPrint("[+]Operation Successfull\n");
#endif
			bytesIO = 0;
		}

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