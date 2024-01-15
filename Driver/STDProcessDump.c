#include "ProcessDump.h"
#include "Utility.h"
#include "Memory.h"


#define Read(a, b, c, d, e)    Read_Process_Memory(a, b, c, d, e)


static ULONG Write_To_Buffer(IN WCHAR* TargetProc, OUT PVOID* pBuffer, OUT PULONG szBuffer )
{
#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Function Called\n");
#endif	
	
	
	ULONG							bufferSZ = 0,
									  status = 1;
	PVOID						   result = NULL,
							  imageBuffer = NULL;
	PEPROCESS					   target = NULL;
	IMAGE_DOS_HEADER			   p_idh = { 0 };
	IMAGE_NT_HEADERS64			   p_inh = { 0 };
    PIMAGE_SECTION_HEADER	sectionHeader = NULL;
	IMAGE_SECTION_HEADER		 section = { 0 };
	ULONG_PTR							 DTB = 0;
	VIRTUAL_ADDRESS			   linear[5] = { 0 };



	target = Process(TargetProc);
	if (!target)
	{
		status = STATUS_FAILED_EPROCESS;
		return status;
	}

	DTB = Process_CR3(target, &status);
	if (DTB == 0)
	{
		return status;
	}
	
	linear[0].pValue = Process_Base(target, &status);
	if (!linear[0].pValue)
	{
		return status;
	}
	
	ObDereferenceObject(target);

	DbgPrint("Read Dos Header\n");
	Read(&p_idh, linear[0], sizeof(IMAGE_DOS_HEADER), DTB, &status);
	if (p_idh.e_magic != IMAGE_DOS_SIG)
	{
		status = STATUS_FAILED_EMAGIC;
		goto end;
	}


	DbgPrint("Read Nt Header\n");
	linear[1].value = linear[0].value + p_idh.e_lfanew;
	Read(&p_inh, linear[1], sizeof(IMAGE_NT_HEADERS64), DTB, &status);
	if (p_inh.Signature != IMAGE_NT_SIG)
	{
		status = STATUS_FAILED_NT_SIG;
		goto end;
	}


	if (p_inh.OptionalHeader.SizeOfImage != 0)
	{
		bufferSZ = p_inh.OptionalHeader.SizeOfImage;

		imageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, bufferSZ, TAG);
		if (!imageBuffer)
		{
			status = STATUS_FAILED_BUFFER_ALLOC;
			goto end;
		}
		RtlZeroMemory(imageBuffer, bufferSZ);
		result = imageBuffer;
	}		
	else
	{
		status = STATUS_FAILED_IMAGE_SIZE;
		goto end;
	}

	DbgPrint("Size Of Image : %lu\n", bufferSZ);


	sectionHeader = (PIMAGE_SECTION_HEADER)(linear[0].value + p_idh.e_lfanew + \
		FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + \
		p_inh.FileHeader.SizeOfOptionalHeader);

	UINT sectionCount = (UINT)p_inh.FileHeader.NumberOfSections;
	
	
	ULONG64 sectionOffset = 0, readLen = 0, sectionRemain = 0, imageOffset = 0, overFlow = 0;

	for (UINT i = 0; i < sectionCount; i++, sectionHeader++)
	{
		linear[2].value = (ULONG64)sectionHeader;
		
		
		Read(&section, linear[2], sizeof(IMAGE_SECTION_HEADER), DTB, &status);
		if (status != STATUS_SUCCESS)
		{
			ExFreePool(result);
			goto end;
		}
		DbgPrint("Read section %d : %s\n", i, section.Name);
		if (section.SizeOfRawData == 0) continue;

		while (sectionOffset < section.SizeOfRawData)
		{
			sectionRemain = (section.SizeOfRawData - sectionOffset);

			linear[3].value = (linear[0].value + section.VirtualAddress + sectionOffset);
			linear[4].value = (((ULONG64)imageBuffer) + section.PointerToRawData + sectionOffset);

			readLen = min(sectionRemain, PAGE_SIZE);
			if (imageOffset + readLen > bufferSZ)
			{
				overFlow = ((imageOffset + readLen) - bufferSZ);

				if ((readLen - overFlow) <= 0)
				{
					break;
				}
				readLen -= overFlow;
			}

			DbgPrint("Reading Section : %d, %s Raw Data\n", i, section.Name);

			Read(linear[4].pValue, linear[3], readLen, DTB, &status);
			if (status != STATUS_SUCCESS)
			{
				ExFreePool(result);
				goto end;
			}

			sectionOffset += readLen;
		}	
	}


#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Operation Successfull\n");
#endif

	status = STATUS_SUCCESS;
	*szBuffer = bufferSZ;
	*pBuffer = result;

	return status;

end:
#ifdef _DEBUG 
	DbgPrint("[!]Write_To_Buffer() Operation Unsuccessfull\n");
#endif

	return status;
}





		

static ULONG Read_Write_File(IN PVOID pBuffer, IN ULONG szBuffer , IN WCHAR* DumpFolder, IN WCHAR* DumpName)
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
		pBuffer, szBuffer, NULL, NULL)))
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


	ULONG			  status = 0,
				    szBuffer = 0;
	PVOID		  pBuffer = NULL;


	
	status = Write_To_Buffer(TargetProc, &pBuffer, &szBuffer);
	if (status != STATUS_SUCCESS)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Read_Write_File() Operation Unsuccessfull\n");
#endif

		return status;
	}

	status = Read_Write_File(pBuffer, szBuffer, DumpFolder, DumpName);
	if (status != STATUS_SUCCESS)
	{

#ifdef _DEBUG 
		DbgPrint("[!]Dump_Process() Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif
	
		return status;
	}
	

#ifdef _DEBUG 
	DbgPrint("[+]Dump_Process() Operation Successfull\n");
#endif
	
	return status;
}




