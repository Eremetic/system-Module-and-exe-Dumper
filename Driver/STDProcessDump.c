#include "ProcessDump.h"
#include "Utility.h"
#include "Memory.h"


#define Read(a, b, c, d, e)    Read_Process_Memory(a, b, c, d, e)

#define OffsetToPointer(Base, Pointer)		((ULONG64)(((ULONG64)(Base)) + ((ULONG64)(Pointer))))

BYTE dosStubCode[] = {
0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


static ULONG Write_To_Buffer(IN WCHAR* TargetProc, OUT PVOID* pBuffer, OUT PULONG64 szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Function Called\n");
#endif	


	ULONG64							   bufferSZ = 0;
	ULONG								 status = 1,
								   sectionCount = 0;
	PVOID					     imageBuffer = NULL, 
									  result = NULL;
	PEPROCESS					      target = NULL;
	IMAGE_DOS_HEADER			      p_idh = { 0 };
	IMAGE_NT_HEADERS64			      p_inh = { 0 };
	PIMAGE_SECTION_HEADER      sectionHeader = NULL;
	ULONG_PTR							    DTB = 0;
	VIRTUAL_ADDRESS			      linear[4] = { 0 };




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

	linear[0].pValue = Process_Base(target, &status);
	if (!linear[0].pValue)
	{
		return status;
	}

	ObDereferenceObject(target);


	Read(((PUCHAR)&p_idh), linear[0], sizeof(IMAGE_DOS_HEADER), DTB, &status);
	if (p_idh.e_magic != IMAGE_DOS_SIG)
	{
		status = STATUS_FAILED_EMAGIC;
		goto end1;
	}

	linear[1].pValue = (PIMAGE_NT_HEADERS64)((LPBYTE)linear[0].value + p_idh.e_lfanew);
	Read(((PUCHAR)&p_inh), linear[1], sizeof(IMAGE_NT_HEADERS64), DTB, &status);
	if (p_inh.Signature != IMAGE_NT_SIG)
	{
		status = STATUS_FAILED_NT_SIG;
		goto end1;
	}

	sectionHeader = (PIMAGE_SECTION_HEADER)(linear[0].value + p_idh.e_lfanew + \
		FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + \
		p_inh.FileHeader.SizeOfOptionalHeader);
	
	linear[2].value = (ULONG64)sectionHeader;
	
	sectionCount = p_inh.FileHeader.NumberOfSections;

	bufferSZ = p_inh.OptionalHeader.SizeOfImage;

	imageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSZ, TAG);
	result = imageBuffer;

	RtlCopyMemory(imageBuffer, &p_idh, sizeof(IMAGE_DOS_HEADER));
	RtlCopyMemory(C_PTR(((ULONG64)imageBuffer + sizeof(IMAGE_DOS_HEADER))), dosStubCode, sizeof(dosStubCode));
	RtlCopyMemory(C_PTR(((ULONG64)imageBuffer + p_idh.e_lfanew)), &p_inh, sizeof(IMAGE_NT_HEADERS64));
	
	for (ULONG i = 0; i < sectionCount; i++, sectionHeader++)
	{
		IMAGE_SECTION_HEADER currectSection = { 0 };
		Read(((PUCHAR)&currectSection), linear[2], sizeof(IMAGE_SECTION_HEADER), DTB, &status);
		if (status != STATUS_SUCCESS)
		{
			goto end2;
		}
#ifdef _DEBUG
		DbgPrint("Reading Section Number : %d, With Section Name  : %s\n", i, (PCHAR)currectSection.Name);
#endif	
		if (currectSection.SizeOfRawData == 0) continue;

		ULONG64 sectionOffset = 0;
		while (sectionOffset < currectSection.SizeOfRawData)
		{
			ULONG64 remaining = currectSection.SizeOfRawData - sectionOffset;
			
			linear[3].value = OffsetToPointer(linear[0].value, (currectSection.VirtualAddress + sectionOffset));
			PUCHAR WritePtr = (PUCHAR)OffsetToPointer(imageBuffer, (currectSection.PointerToRawData + sectionOffset));
			
			ULONG64 readLen = min(remaining, PAGE_SIZE);
			
			ULONG64 imageOffset = currectSection.PointerToRawData + sectionOffset;
			if (imageOffset + readLen > bufferSZ)
			{
				ULONG64 overFlow = OffsetToPointer(imageOffset, readLen) - bufferSZ;
				if (readLen - overFlow <= 0)
				{
					break;
				}
				readLen -= overFlow;
			}

			Read(WritePtr, linear[3], readLen, DTB, &status);
			if (status != STATUS_SUCCESS)
			{
				goto end2;
			}

			sectionOffset += readLen;
		}
		
		
	}

	* szBuffer = bufferSZ;
	* pBuffer = result;


#ifdef _DEBUG 
	DbgPrint("[+]Write_To_Buffer() Operation Successfull\n");
#endif

	return STATUS_SUCCESS;

end2:
	ExFreePool(result);
end1:

#ifdef _DEBUG 
	DbgPrint("[!]Write_To_Buffer() Operation Unsuccessfull\n");
#endif

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
	PVOID		  pBuffer = NULL;
				   

					
	


	status = Write_To_Buffer(TargetProc, &pBuffer ,&szBuffer);
	if (status != STATUS_SUCCESS)
	{
		goto end;
	}
	

	status = Read_Write_File(pBuffer, szBuffer, DumpFolder, DumpName);
	if (status != STATUS_SUCCESS)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Dump_Process() Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif
	
		return status;
	}
	
	end:
#ifdef _DEBUG 
	DbgPrint("[+]Dump_Process() Operation Successfull\n");
#endif
	
	return status;
}





/// no clue if this will work 
ULONG Fix_Pe(IN PVOID baseAddr)
{
#ifdef _DEBUG 
	DbgPrint("[+]Fix_Pe() Function Called\n");
#endif
	
	PIMAGE_DOS_HEADER  dos_Header = NULL;
	PIMAGE_NT_HEADERS64 nt_Header = NULL;
	PIMAGE_SECTION_HEADER  iatFix = NULL;
	ULONG subSize = 0, status = 0, iatData = 0;

	

#define IMAGE_FIRST_SECTION(nt_Header)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(nt_Header)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((nt_Header))->FileHeader.SizeOfOptionalHeader))
	
	DbgPrint("dosHeader\n");

	dos_Header = (PIMAGE_DOS_HEADER)baseAddr;
	if (dos_Header->e_magic != IMAGE_DOS_SIG)
	{
		status = STATUS_FAILED_EMAGIC;
		goto end;
	}
	
	DbgPrint("ntHeader\n");
	nt_Header = (PIMAGE_NT_HEADERS64)((LPBYTE)baseAddr + dos_Header->e_lfanew);
	if (nt_Header->Signature != IMAGE_NT_SIG)
	{
		status = STATUS_FAILED_NT_SIG;
		goto end;
	}

	DbgPrint("sectionHeader\n");
	iatFix = IMAGE_FIRST_SECTION(nt_Header);
	if (!iatFix)
	{
		status = STATUS_FAILED_FIRST_SECTION;
		goto end;
	}

	DbgPrint("Fixing Data Directories\n");
	
	nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

	for (int j = nt_Header->OptionalHeader.NumberOfRvaAndSizes; j < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; j++)
	{
		nt_Header->OptionalHeader.DataDirectory[j].VirtualAddress = 0;
		nt_Header->OptionalHeader.DataDirectory[j].Size = 0;
	}

	nt_Header->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	nt_Header->OptionalHeader.SizeOfHeaders = AlignValue((ULONG64)subSize + nt_Header->OptionalHeader.SizeOfHeaders + \
	(nt_Header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), nt_Header->OptionalHeader.FileAlignment);

	
	DbgPrint("Removing IAT\n");
	
	iatData = nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

	nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

	if (iatData != 0)
	{
		for (int n = 0; n < nt_Header->FileHeader.NumberOfSections; n++, iatFix++)
		{
			if (iatFix->VirtualAddress <= iatData && iatFix->VirtualAddress + iatFix->Misc.VirtualSize > iatData)
			{
				iatFix->Characteristics |= MEMORYREAD | MEMORYWRITE;
			}
		}
	}


#ifdef _DEBUG 
	DbgPrint("[+Fix_Pe() Operation Successfull\n");
#endif

	return STATUS_SUCCESS;

end:
#ifdef _DEBUG 
	DbgPrint("[+Fix_Pe() Operation Unsuccessfull\n");
#endif

	return status;
}






///for getting IAT Thunks, Not Sure IF i Need This Yet
//
//PIMPORT_INFO Import_IAT(IN ULONG64 DTblBase, IN PVOID baseAddr, OUT PULONG returnstatus, PULONG status)
//{
//
//	ULONG					   impIatStatus = 1;
//	LPBYTE           pBase = ((LPBYTE)baseAddr);
//	PVOID                         result = NULL;
//	IMAGE_DOS_HEADER         dos_Header = { 0 };
//	IMAGE_NT_HEADERS64		  nt_Header = { 0 };
//	PIMAGE_IMPORT_DESCRIPTOR importDesc = { 0 };
//	PIMAGE_THUNK_DATA64		    ogThunk = { 0 },
//							 firstThunk = { 0 };
//	PIMPORT_INFO	          importInfo = NULL;
//	PIMAGE_IMPORT_BY_NAME   currentThunk = NULL;
//	VIRTUAL_ADDRESS			   vAddr[3] = { 0 };
//	
//	
//	vAddr[0].pValue = baseAddr;
//	Read(&dos_Header, vAddr[0], sizeof(IMAGE_DOS_HEADER), DTblBase, &impIatStatus);
//	if (dos_Header.e_magic != IMAGE_DOS_SIG)
//	{
//		*status = STATUS_FAILED_EMAGIC;
//		return NULL;
//	}
//
//	vAddr[1].value = (pBase + dos_Header.e_lfanew);
//	Read(&nt_Header, vAddr[1], sizeof(IMAGE_NT_HEADERS64), DTblBase, &impIatStatus);
//	if (nt_Header.Signature != IMAGE_NT_SIG)
//	{
//		*status = STATUS_FAILED_NT_SIG;
//		return NULL;
//	}
//
//	if ((nt_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) == 0)
//	{
//		return NULL;
//	}
//
//	vAddr[2].value = (pBase + nt_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
//	SIZE_T readLen = nt_Header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//	Read(importDesc, vAddr[2], readLen, DTblBase, &impIatStatus);
//	
//
//
//	while (importDesc->FirstThunk)
//	{
//		importInfo->module_name = *(char*)(pBase + importDesc->Name);
//		
//		ogThunk = *(PIMAGE_THUNK_DATA64*)((ULONG64)pBase + importDesc->OriginalFirstThunk);
//		firstThunk = *(PIMAGE_THUNK_DATA64*)((ULONG64)pBase + importDesc->FirstThunk);
//
//		while (ogThunk->u1.Function)
//		{
//			currentThunk = *(PIMAGE_IMPORT_BY_NAME*)((ULONG64)pBase + ogThunk->u1.AddressOfData);
//			
//			importInfo->functionData->name = currentThunk->Name;
//			importInfo->functionData->address = &firstThunk->u1.Function;
//
//			
//			importInfo->functionData = importInfo->functionData->Next;
//			++ogThunk;
//			++firstThunk;
//		}
//		
//		
//		importInfo = importInfo->Next;
//		importDesc++;
//	}
//
//	return importInfo;
//}
//
//
//
//BOOL Resolve_IAT(PIMPORT_INFO importInfo)
//{
//
//}