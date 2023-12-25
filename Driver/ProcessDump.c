#include "ProcessDump.h"
#include "Utility.h"


#define Read(a, b, c) Copy_Physical_Memory(a, b, c)


PVOID Process_Query(IN CLIENT_ID cID, OUT PULONG status)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_Query() Function Called\n");
#endif

	NTSTATUS							check;
	PEPROCESS				   process = NULL;
	PVOID					  baseAddr = NULL;

	

	if (!NT_SUCCESS(check = PsLookupProcessByProcessId(cID.UniqueProcess, &process)))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Get EPROCESS With ERROR : 0x%I64x\n", check);
#endif	
		*status = STATUS_FAILED_EPROCESS;
	}

	baseAddr = PsGetProcessSectionBaseAddress(process);

	if (baseAddr)
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
#endif

		*status = STATUS_SUCCESS;
		return baseAddr;
	}
	
#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull\n");
#endif
	
	return NULL;
}


static ULONG Process_Size(IN PVOID BaseAddr, OUT PULONG szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_Size() Function Called\n");
#endif

	ULONG						  status = 1,
							  szSections = 0;
	PVOID			   		  pBuffer = NULL;
	PVOID				 bufferHeader = NULL;
	PIMAGE_DOS_HEADER			p_idh = NULL;
	PIMAGE_NT_HEADERS64			p_inh = NULL;
	PIMAGE_SECTION_HEADER       p_ish = NULL;
	

#define IMAGE_FIRST_SECTION(p_inh)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(p_inh)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((p_inh))->FileHeader.SizeOfOptionalHeader))


		
	pBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, _2PAGES, TAG);
	if(!pBuffer)
	{
#ifdef _DEBUG 
			DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_BUFFER_ALLOC;
		return status;
	}
	
	Read(pBuffer, BaseAddr, _2PAGES);
	
	bufferHeader = pBuffer;
	
	if (!NT_SUCCESS(status = PE_Check(pBuffer)))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif
		ExFreePool(bufferHeader);
		return status;
	}

	p_idh = (PIMAGE_DOS_HEADER)pBuffer;
	p_inh = (PIMAGE_NT_HEADERS64)((LPBYTE)pBuffer + p_idh->e_lfanew);
	p_ish = IMAGE_FIRST_SECTION(p_inh);
	if (p_ish)
	{
		for (int i = 0; i < p_inh->FileHeader.NumberOfSections; i++, p_ish++)
		{
			if (p_ish->SizeOfRawData == 0) continue;
			szSections += p_ish->SizeOfRawData;
		}
	}
	else
	{
		status = STATUS_FAILED_FIRST_SECTION;
	}

	

	ExFreePool(bufferHeader);

	if (szSections != 0)
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
#endif

		*szBuffer = szSections;
		return STATUS_SUCCESS;
	}
	

#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull\n");
#endif

	return STATUS_FAILED_IMAGE_SIZE;
}

		

static ULONG Read_Write_File(IN PVOID BaseAddr, IN WCHAR* DumpFolder, IN WCHAR* DumpName, IN ULONG szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Write_File() Function Called\n");
#endif


	ULONG						  status = 0;
	PVOID				  imageBuffer = NULL,
		     			  imageHeader = NULL;
	PIMAGE_DOS_HEADER			p_idh = NULL;
	PIMAGE_NT_HEADERS64			p_inh = NULL;
	PIMAGE_SECTION_HEADER       p_ish = NULL;


#define IMAGE_FIRST_SECTION(p_inh)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(p_inh)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((p_inh))->FileHeader.SizeOfOptionalHeader))


	imageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, (szBuffer + (_2PAGES / 2)), TAG);
	if (!imageBuffer)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif
		return STATUS_FAILED_BUFFER_ALLOC;
	}

	Read(imageBuffer, BaseAddr, szBuffer);

	imageHeader = imageBuffer;

	if (!NT_SUCCESS(status = PE_Check(imageBuffer)))
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif
		ExFreePool(imageHeader);
		return status;
	}

	p_idh = (PIMAGE_DOS_HEADER)imageBuffer;
	p_inh = (PIMAGE_NT_HEADERS64)((LPBYTE)imageBuffer + p_idh->e_lfanew);
	p_ish = IMAGE_FIRST_SECTION(p_inh);
	if (p_ish)
	{
		INT64 Offset = 0;
		for (int i = 0; i < p_inh->FileHeader.NumberOfSections; i++, p_ish++)
		{
			if (p_ish->SizeOfRawData == 0) continue;
			
			Read(C_PTR(((UCHAR*)imageBuffer + Offset)), C_PTR(p_ish->PointerToRawData), (ULONG)p_ish->SizeOfRawData);
			Offset += p_ish->SizeOfRawData;
		}
	}
	else
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		status = STATUS_FAILED_FIRST_SECTION;
		ExFreePool(imageHeader);
		return status;
	}
	

/////////////////////////////////////////////////////////////////////////////////
	
	IO_STATUS_BLOCK				  misc_sb = { 0 };
	OBJECT_ATTRIBUTES		   dir_objatt = { 0 },
						      file_objatt = { 0 };
	HANDLE					   file_Handle = NULL,
							    Dir_Handle = NULL;
	UNICODE_STRING				 file_Dir = { 0 },
								dump_File = { 0 };

	///converting wchar to unicode
	RtlInitUnicodeString(&file_Dir, DumpFolder);
	RtlInitUnicodeString(&dump_File, DumpName);



	InitializeObjectAttributes(&dir_objatt, &file_Dir, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(status = ZwCreateFile(&Dir_Handle, DELETE,
		&dir_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_DIRECTORY, 0,
		FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0)))
	{

		InitializeObjectAttributes(&file_objatt, &dump_File, OBJ_KERNEL_HANDLE, NULL, NULL);

		if (NT_SUCCESS(status = ZwCreateFile(&file_Handle, GENERIC_ALL,
			&file_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
			FILE_SUPERSEDE, FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
		{
			///writing to file
			if (NT_SUCCESS(status = ZwWriteFile(
				file_Handle, NULL, NULL, NULL, &misc_sb,
				imageBuffer, szBuffer, NULL, NULL)))
			{
#ifdef _DEBUG 
				DbgPrint("[+]Operation Successfull\n");
#endif
			}
			else
			{

#ifdef _DEBUG 
				DbgPrint("[!]Operation Unsuccessfull\n");
#endif

				ZwDeleteFile(&dir_objatt);
				ZwDeleteFile(&file_objatt);
				status = STATUS_FAILED_TO_WRITE;
				goto end3;
			}
		}
		else
		{

#ifdef _DEBUG 
			DbgPrint("[!]Operation Unsuccessfull\n");
#endif

			status = STATUS_FAILED_TO_CREATE_FILE;
			goto end2;
		}
	}
	else
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		status = STATUS_FAILED_TO_CREATE_DIR;
		goto end1;
	}

	end3:
	ZwClose(file_Handle);
	end2:
	ZwClose(Dir_Handle);
	end1:
	ExFreePool(imageHeader);

	return status;
}





ULONG Dump_Process(IN WCHAR* TargetProc, IN WCHAR* DumpFolder, IN WCHAR* DumpName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Dump_Process() Function Called\n");
#endif


	ULONG			 status = 0,
				   szBuffer = 0;
	PVOID		baseAddr = NULL;
	CLIENT_ID	    cID = { 0 };
	
	cID = Process_ID(TargetProc);
	if (!cID.UniqueProcess)
	{
		return STATUS_FAILED_PROC_ID;
	}

	baseAddr = Process_Query(cID, &status);
	if (baseAddr)
	{
		if (NT_SUCCESS(status = Process_Size(baseAddr, &szBuffer)))
		{
			if (szBuffer != 0)
			{
				if (NT_SUCCESS(status = Read_Write_File(baseAddr, DumpFolder, DumpName, szBuffer)))
				{
#ifdef _DEBUG 
					DbgPrint("[!]Operation Successfull\n");
#endif
					return status;
				}
				else
					goto end;
			}
			else
				goto end;
		}
		else
			goto end;
	}
	else
		goto end;
	
	end:
	

#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif
	
	
	return status;
}

