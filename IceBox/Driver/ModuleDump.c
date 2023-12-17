#include "ModuleDump.h"
#include "Utility.h"




///module query with zwquery system information
static PVOID Query_Module(IN WCHAR* module, OUT PULONG ImageSize)
{
#ifdef _DEBUG 
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[+]Query_Module() Function Called\n");
#endif
	
	PSYSTEM_MODULE_INFORMATION   p_smi;
	ULONG		      szBuffer = 0,
			       szimage = 0;
	ANSI_STRING	      temp = { 0 };
	UNICODE_STRING	cur_Module = { 0 };
	PVOID		  Base_Addr = NULL;

	///calling to get buffer size
	ZwQuerySystemInformation(SystemModuleInformation, 0, szBuffer, &szBuffer);
	if (szBuffer == 0)
	{
		return NULL;
	}
	///allocating memory for real call
	p_smi = ExAllocatePool2(POOL_FLAG_NON_PAGED, szBuffer, TAG);
	if (!p_smi)
	{
		return NULL;
	}
	///real call to get information
	ZwQuerySystemInformation(SystemModuleInformation, p_smi, szBuffer, &szBuffer);

	
	/// query through the modules to find the bass address and size
	PSYSTEM_MODULE_ENTRY p_me = p_smi->Module;

	for (ULONG_PTR i = 0; i < p_smi->Count; i++)
	{	
		///converting uchar(ansi) to unicode
		RtlInitAnsiString(&temp, (PCSZ)((CHAR*)(p_me[i].FullPathName + p_me[i].OffsetToFileName)));  
		RtlAnsiStringToUnicodeString(&cur_Module, &temp, TRUE);
		
		///finding user selected module
		if (RSHasher(module, cur_Module.Buffer))
		{
			Base_Addr = p_me[i].ImageBase;
			szimage = p_me[i].ImageSize;
			break;
		}	
	}

	if (Base_Addr != NULL && szimage != 0)
	{	
#ifdef _DEBUG 
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[+]Operation Successfull\n");
#endif

		ExFreePoolWithTag(p_smi, TAG);
		*ImageSize = szimage;
		return Base_Addr;
	}

#ifdef _DEBUG 
	DbgPrint("[!]Operation UnSuccessfull\n");
#endif

	return NULL;
}






static ULONG Read_Write_File(IN LPVOID BaseAddr, IN WCHAR* DumpFolder, IN WCHAR* DumpName, IN ULONG szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Write_File() Function Called\n");
#endif


	ULONG			    status = 0;
	MM_COPY_ADDRESS 	p_Copy = { 0 };
	SIZE_T			     Bytes = 0;
	LPVOID			pBuffer = NULL;

	///securing and zero struct
	RtlSecureZeroMemory(&p_Copy, sizeof(MM_COPY_ADDRESS));

	///getting physical addres of module base
	p_Copy.PhysicalAddress = MmGetPhysicalAddress(BaseAddr);

	///allocating new buffer for dump
	pBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, szBuffer, TAG);
	if (pBuffer != NULL)
	{
		__try
		{
			///reading physical memory
			KeEnterCriticalRegion();

			MmCopyMemory(pBuffer, p_Copy, szBuffer, MM_COPY_MEMORY_PHYSICAL, &Bytes);
			status = STATUS_SUCCESS;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{

#ifdef _DEBUG 
			DbgPrint("[!]Operation UnSuccessfull\n");
#endif

			status = STATUS_MM_COPY_FAILED;
			goto end;
		}
	}
	else
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_BUFFER_ALLOC;
		goto end;
	}

	KeLeaveCriticalRegion();
	///virtual to raw header fix
	if (!NT_SUCCESS(status = Fix_Headers(pBuffer)))
	{
		return status;
	}


	IO_STATUS_BLOCK				  dirp_sb = { 0 },
								 filep_sb = { 0 },
								writep_sb = { 0 };
	OBJECT_ATTRIBUTES		   dir_objatt = { 0 },
						      file_objatt = { 0 };
	HANDLE					   file_Handle = NULL,
							    Dir_Handle = NULL;
	UNICODE_STRING				 file_Dir = { 0 },
								dump_File = { 0 };

	///converting wchar to unicode
	RtlInitUnicodeString(&file_Dir, DumpFolder);
	RtlInitUnicodeString(&dump_File, DumpName);
	
	
	///securing memory and zeroing structs
	RtlSecureZeroMemory(&dirp_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&filep_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&writep_sb, sizeof(IO_STATUS_BLOCK));
	RtlSecureZeroMemory(&dir_objatt, sizeof(OBJECT_ATTRIBUTES));
	RtlSecureZeroMemory(&file_objatt, sizeof(OBJECT_ATTRIBUTES));
	

	InitializeObjectAttributes(&dir_objatt, &file_Dir, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (NT_SUCCESS(status = ZwCreateFile(&Dir_Handle, DELETE,
	&dir_objatt, &dirp_sb, NULL, FILE_ATTRIBUTE_DIRECTORY, 0,
	FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0)))
	{
		
		InitializeObjectAttributes(&file_objatt, &dump_File, OBJ_KERNEL_HANDLE, NULL, NULL);

		if (NT_SUCCESS(status = ZwCreateFile(&file_Handle, GENERIC_ALL,
			&file_objatt, &filep_sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
			FILE_SUPERSEDE, FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
		{
			///writing to file
			if (NT_SUCCESS(status = ZwWriteFile(
				file_Handle, NULL, NULL, NULL, &writep_sb,
				pBuffer, szBuffer, NULL, NULL)))
			{
#ifdef _DEBUG 
				DbgPrint("[+]Operation Successfull\n");
#endif
			}
			else
			{

#ifdef _DEBUG 
				DbgPrint("[!]Operation UnSuccessfull\n");
#endif

				ZwDeleteFile(&dir_objatt);
				ZwDeleteFile(&file_objatt);
				status = STATUS_FAILED_TO_WRITE;
			}
		}
		else
		{

#ifdef _DEBUG 
			DbgPrint("[!]Operation UnSuccessfull\n");
#endif

			status = STATUS_FAILED_TO_CREATE_FILE;
		}
	}
	else
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_TO_CREATE_DIR;
	}

	

		ZwClose(Dir_Handle);
		ZwClose(file_Handle);
	end:

	return status;
}






ULONG Dump_Module(IN WCHAR* DumpFolder, IN WCHAR* DumpName, IN WCHAR* Module)
{
#ifdef _DEBUG 
	DbgPrint("[+]Dump_Module() Function Called\n");
#endif
	
	ULONG				status = 0;
	PVOID		 	  Base_Addr = NULL;
	ULONG			    Image_Size = 0;
		

	///querying module information
	Base_Addr = Query_Module(Module, &Image_Size);
	if (Base_Addr)
	{
		///check file format is correct
		if (NT_SUCCESS(status = PE_Check(Base_Addr)))
		{

			///writing buffer to file(fixing headers in write_file function)
			if (NT_SUCCESS(status = Read_Write_File(Base_Addr, DumpFolder, DumpName, Image_Size)))
			{
#ifdef _DEBUG 
				DbgPrint("[+]Operation Successfull\n");
#endif

				return status;
			}
		}
	}
	else
	{
		status = STATUS_FAILED_BASE_ADDR;
	}
#ifdef _DEBUG 
	DbgPrint("[!]Operation UnSuccessfull With Status 0x%I64x\n", status);
#endif

	return status;
}
