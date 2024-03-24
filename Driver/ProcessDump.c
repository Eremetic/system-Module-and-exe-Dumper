#include "ProcessDump.h"
#include "Utility.h"
#include "Memory.h"


#define Read(a, b, c, d, e)    Read_Process_Memory(a, b, c, d, e)


static ULONG Write_To_Buffer(IN WCHAR* TargetProc, OUT PVOID* pBuffer, OUT PULONG64 szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Function Called\n");
#endif	


	ULONG64							   bufferSZ = 0;
	ULONG								 status = 1;
	PVOID					     imageBuffer = NULL, 
								bufferHeader = NULL;
	PEPROCESS					      target = NULL;
	IMAGE_DOS_HEADER			      p_idh = { 0 };
	IMAGE_NT_HEADERS64			      p_inh = { 0 };
	ULONG_PTR							    DTB = 0;
	VIRTUAL_ADDRESS				   baseAddr = { 0 };
	VIRTUAL_ADDRESS				   ntHeader = { 0 };



	target = Process(TargetProc);
	if (!target)
	{

		return STATUS_FAILED_EPROCESS;
	}

	DTB = Process_CR3(target, &status);
	if (DTB == 0)
	{
		return status;
	}

	baseAddr.pValue = Process_Base(target, &status);
	if (!baseAddr.pValue)
	{
		return status;
	}

	


	Read(C_PTR(&p_idh), baseAddr, sizeof(IMAGE_DOS_HEADER), DTB, &status);
	if (p_idh.e_magic != IMAGE_DOS_SIG)
	{
		status = STATUS_FAILED_EMAGIC;
		goto end1;
	}

	ntHeader.pValue = (PIMAGE_NT_HEADERS64)((LPBYTE)baseAddr.value + p_idh.e_lfanew);
	Read(C_PTR(&p_inh), ntHeader, sizeof(IMAGE_NT_HEADERS64), DTB, &status);
	if (p_inh.Signature != IMAGE_NT_SIG)
	{
		status = STATUS_FAILED_NT_SIG;
		goto end1;
	}


	bufferSZ = p_inh.OptionalHeader.SizeOfImage;

	imageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSZ, TAG);
	if (!imageBuffer)
	{
		status = STATUS_FAILED_BUFFER_ALLOC;
		goto end1;
	}
	bufferHeader = imageBuffer;

	VIRTUAL_ADDRESS readAddr = { 0 };
	
	readAddr = baseAddr;
	
	ULONG_PTR readOffset = 0;
	ULONG_PTR writeOffset = 0;	
	ULONG_PTR bufferBase = U_PTR(imageBuffer);
	ULONG readLen = 0;
	ULONG_PTR totalRead = 0;
	PMDL pMdl = NULL;
	PVOID mdlBuffer = NULL;
	
	
	if (!Attach_To_Pocess(target))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Attach To Target Process\n");
#endif	
		goto end2;
	}
	
	while (totalRead < bufferSZ)
	{			
		readLen = U_LNG(min(PAGE_SIZE, bufferSZ - totalRead));
	
		readAddr.value = PointerToOffset(baseAddr.value, readOffset);
		writeOffset = PointerToOffset(bufferBase, readOffset);

		pMdl = IoAllocateMdl(readAddr.pValue, readLen, FALSE, FALSE, NULL);
		if (!pMdl)
		{
			status = U_LNG(STATUS_INSUFFICIENT_RESOURCES);
			goto end2;
		}
		__try
		{
			MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = U_LNG(GetExceptionCode());
#ifdef _DEBUG 
			DbgPrint("[!]MmProbeLockPages Failed With ERROR : 0x%I32X\n", status);
#endif	
			
			IoFreeMdl(pMdl);
			goto end2;
		}
	
		mdlBuffer = MmGetSystemAddressForMdl(pMdl);
		if (!mdlBuffer)
		{
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
			status = U_LNG(STATUS_INSUFFICIENT_RESOURCES);
			goto end2;
		}

		RtlCopyMemory(C_PTR(writeOffset), mdlBuffer, readLen);

		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);

		readOffset += readLen;
	}

	
	DbgPrint("[+]Finished Reading Process\n");
	if (!Detach_From_Process(target))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Detach From Target Processl\n");
#endif
		goto end2;
	}

	ObDereferenceObject(target);
	* szBuffer = bufferSZ;
	* pBuffer = bufferHeader;


#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Operation Successfull\n");
#endif

	return STATUS_SUCCESS;

end2:
	ExFreePool(bufferHeader);
end1:

#ifdef _DEBUG 
	DbgPrint("[!]Write_To_Buffer() Operation Unsuccessfull\n");
#endif
	if (!Detach_From_Process(target))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Detach From Target Processl\n");
#endif
		goto end2;
	}
	ObDereferenceObject(target);
	return status;
}





		

static ULONG Read_Write_File(IN PVOID pBuffer, IN ULONG64 szBuffer , IN WCHAR* DumpFolder, IN WCHAR* DumpName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Write_File() Function Called\n");
#endif


	ULONG					    status = 0;
	PVOID			   bufferHeader = NULL;
	IO_STATUS_BLOCK		   misc_sb = { 0 };
	OBJECT_ATTRIBUTES	dir_objatt = { 0 },
					   file_objatt = { 0 };
	HANDLE				file_Handle = NULL,
					     Dir_Handle = NULL;
	UNICODE_STRING		  file_Dir = { 0 },
						 dump_File = { 0 };

	///converting wchar to unicode
	RtlInitUnicodeString(&file_Dir, DumpFolder);
	RtlInitUnicodeString(&dump_File, DumpName);
	
	bufferHeader = pBuffer;

	if (!NT_SUCCESS(status = PE_Check(pBuffer)))
	{
		ExFreePool(bufferHeader);
		goto end;
	}

	InitializeObjectAttributes(&dir_objatt, &file_Dir, OBJ_KERNEL_HANDLE, NULL, NULL);


	if (!NT_SUCCESS(status = ZwCreateFile(&Dir_Handle, DELETE,
		&dir_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_DIRECTORY, 0,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0)))
	{
		status = STATUS_FAILED_TO_CREATE_DIR;
		ExFreePool(bufferHeader);
		goto end;
	}


	InitializeObjectAttributes(&file_objatt, &dump_File, OBJ_KERNEL_HANDLE, NULL, NULL);


	if (!NT_SUCCESS(status = ZwCreateFile(&file_Handle, GENERIC_ALL,
		&file_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
		FILE_SUPERSEDE, FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
	{
		status = STATUS_FAILED_TO_CREATE_FILE;
		ZwClose(Dir_Handle);
		ExFreePool(bufferHeader);
		goto end;
	}
			
	

	if (NT_SUCCESS(status = ZwWriteFile(
		file_Handle, NULL, NULL, NULL, &misc_sb,
		pBuffer, (ULONG)szBuffer, NULL, NULL)))
	{
#ifdef _DEBUG 
		DbgPrint("[+]Read_Write_File() Operation Successfull\n");
#endif
		ZwClose(Dir_Handle);
		ZwClose(file_Handle);
		ExFreePool(bufferHeader);
		return status;
	}
	else
	{
		ZwDeleteFile(&dir_objatt);
		ZwDeleteFile(&file_objatt);
		status = STATUS_FAILED_TO_WRITE;
		ZwClose(Dir_Handle);
		ZwClose(file_Handle);
		ExFreePool(bufferHeader);
		goto end;
	}

end:
#ifdef _DEBUG 
	DbgPrint("[!]Read_Write_File() Operation Unsuccessfull\n");
#endif

	return status;
}





ULONG Dump_Process(IN WCHAR* TargetProc, IN WCHAR* DumpFolder, IN WCHAR* DumpName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Dump_Process() Function Called\n");
#endif


	ULONG			  status = 0;
	ULONG64			szBuffer = 0;
	PVOID		  pBuffer = NULL, bufferHeader = NULL;
				   				
	status = Write_To_Buffer(TargetProc, &pBuffer ,&szBuffer);
	if (status != STATUS_SUCCESS)
	{
		goto end;
	}
	
	bufferHeader = pBuffer;
	if (!NT_SUCCESS(status = Fix_Headers(bufferHeader)))
	{
		ExFreePool(pBuffer);
		goto end;
	}

	
	status = Read_Write_File(pBuffer, szBuffer, DumpFolder, DumpName);
	if (status == STATUS_SUCCESS)
	{

#ifdef _DEBUG 
		DbgPrint("[+]Dump_Process() Operation Successfull\n");
#endif

		return status;
	}
	
	end:
#ifdef _DEBUG 
	DbgPrint("[!]Dump_Process() Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif
	
	return status;
}








