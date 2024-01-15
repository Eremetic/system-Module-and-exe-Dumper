#include "ProcessDump.h"
#include "Utility.h"



#define Read(a, b, c)   Copy_Physical_Memory(a, b, c)


static PVOID Check_RW(PVOID pointer, SIZE_T size)
{
	MEMORY_BASIC_INFORMATION memInfo = { 0 };

	if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), pointer, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
	{
		if (!(((uintptr_t)memInfo.BaseAddress + memInfo.RegionSize) < (((uintptr_t)pointer + size))))
		{
			if (memInfo.State & MEM_COMMIT || !(memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				if (memInfo.Protect & PAGE_EXECUTE_READWRITE || memInfo.Protect & PAGE_EXECUTE_WRITECOPY || memInfo.Protect & PAGE_READWRITE || memInfo.Protect & PAGE_WRITECOPY)
				{
					return pointer;
				}
			}
		}
	}
	return NULL;
}



static WCHAR* Check_Exe(IN WCHAR* Target, IN WCHAR* Created, IN USHORT CrtDLen)
{
#ifdef _DEBUG 
	DbgPrint("[+]Check_Exe() Function Called\n");
#endif

	size_t procStrlen = wcslen(Target);
	WCHAR Check[MAX_PATH] = { 0 };
	WCHAR* result = { 0 };

	for (size_t i = CrtDLen - procStrlen; i < CrtDLen; i++)
	{
		for (size_t j = 0; j < procStrlen; j++)
		{
			Check[j] = Created[i];
		}
	}

	result = (WCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (wcslen(Check) * sizeof(WCHAR)), TAG);
	if (!result)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Failed To Allocate Buffer\n");
#endif

		return NULL;
	}
#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

	return result;
}



//
//
//static PVOID Ldr_Data(IN WCHAR* ProcName, IN PEPROCESS Target, OUT PVOID* baseAddress ,OUT PULONG Status)
//{
//#ifdef _DEBUG 
//	DbgPrint("[+]Ldr_Data() Function Called\n");
//#endif
//	
//	PPEB64						  peb = NULL;
//	PPEB_LDR_DATA				 Pldr = NULL;
//	PKLDR_DATA_TABLE_ENTRY  PLdrEntry = NULL;
//	PVOID					 BaseAddr = NULL,
//					       EntryPoint = NULL;
//
//	
//	
//	BaseAddr = PsGetProcessSectionBaseAddress(Target);
//	if (!BaseAddr)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		* Status = STATUS_FAILED_BASE_ADDR;
//		return NULL;
//	}
//	
//	peb = (PPEB64)(PsGetProcessPeb(Target));
//
//	peb = Check_RW(peb, sizeof(PEB64));
//	if (!peb)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		* Status = STATUS_FAILED_PEB;
//		return NULL;
//	}
//
//	Pldr = (PPEB_LDR_DATA)(peb->Ldr);
//
//	Pldr = Check_RW(Pldr, sizeof(PEB_LDR_DATA));
//	if (!Pldr)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		* Status = STATUS_FAILED_PEB_LDR;
//		return NULL;
//	}
//
//	PLdrEntry = (PKLDR_DATA_TABLE_ENTRY)(Pldr->InMemoryOrderModuleList.Flink);
//
//	PLdrEntry = Check_RW(PLdrEntry, sizeof(KLDR_DATA_TABLE_ENTRY));
//	if (!PLdrEntry)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		* Status = STATUS_FAILED_LDR_ENTRY;
//		return NULL;
//	}
//
//
//	while (PLdrEntry)
//	{
//
//		if (PLdrEntry->FullDllName.Buffer)
//		{
//			if (RSHasher(PLdrEntry->FullDllName.Buffer, ProcName))
//			{
//				EntryPoint = PLdrEntry->EntryPoint;
//			}
//		}
//
//		PLdrEntry = *(PKLDR_DATA_TABLE_ENTRY*)(PLdrEntry);
//	}
//
//
//	if (BaseAddr != NULL && EntryPoint != NULL)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[+]Operation Successfull\n");
//#endif	
//
//		* Status = STATUS_SUCCESS;
//		*baseAddress = BaseAddr;
//		return EntryPoint;
//	}
//
//#ifdef _DEBUG 
//	DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//	* Status = (ULONG)STATUS_UNSUCCESSFUL;
//	return NULL;
//}
//
//
//
//static unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue)
//{
//	unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
//	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);
//
//	return NewDr7Register;
//}
//
//
//
//static ULONG SetHardwareBreakingPnt(IN HANDLE hThread, IN PVOID pAddress, enum _DRX Drx)
//{
//	ULONG status = 1;
//	
//	if (!pAddress)
//		return FALSE;
//
//	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
//
//
//	if (!NT_SUCCESS(status = PsGetContextThread(hThread, &ThreadCtx)))
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//		
//		status = STATUS_FAILED_GET_CONTEXT;
//		return status;
//	}
//		
//
//
//	switch (Drx)
//	{
//	case Dr0:
//	{
//		if (!ThreadCtx.Dr0)
//			ThreadCtx.Dr0 = (ULONG64)pAddress;
//		break;
//	}
//	case Dr1:
//	{
//		if (!ThreadCtx.Dr1)
//			ThreadCtx.Dr1 = (ULONG64)pAddress;
//		break;
//	}
//	case Dr2:
//	{
//		if (!ThreadCtx.Dr2)
//			ThreadCtx.Dr2 = (ULONG64)pAddress;
//		break;
//	}
//	case Dr3:
//	{
//		if (!ThreadCtx.Dr3)
//			ThreadCtx.Dr3 = (ULONG64)pAddress;
//		break;
//	}
//	default:
//		return FALSE;
//	}
//
//
//
//	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 1);
//
//
//	if (!NT_SUCCESS(status = PsSetContextThread(hThread, &ThreadCtx)))
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		status = STATUS_FAILED_SET_CONTEXT;
//		return status;
//	}
//		
//
//#ifdef _DEBUG 
//	DbgPrint("[!]Operation Successfull\n");
//#endif
//
//	return STATUS_SUCCESS;
//}
//
//
//
//
//
//static PVOID Write_To_Buffer(IN PVOID BaseAddr, OUT PULONG szBuffer, OUT PULONG status)
//{
//#ifdef _DEBUG 
//	DbgPrint("[+]Write_To_Buffer() Function Called\n");
//#endif	
//
//
//	ULONG						bufferSZ = 0;
//	PVOID				  imageBuffer = NULL;
//	PIMAGE_DOS_HEADER			p_idh = NULL;
//	PIMAGE_NT_HEADERS			p_inh = NULL;
//
//
//	p_idh = (PIMAGE_DOS_HEADER)BaseAddr;
//	if (p_idh->e_magic != IMAGE_DOS_SIG)
//	{
//
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		*status = STATUS_FAILED_EMAGIC;
//		return NULL;
//	}
//
//
//	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
//	if (p_inh->Signature != IMAGE_NT_SIG)
//	{
//
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		*status = STATUS_FAILED_NT_SIG;
//		return NULL;
//	}
//
//
//	bufferSZ = p_inh->OptionalHeader.SizeOfImage;
//
//
//	if (bufferSZ != 0)
//	{
//		imageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, bufferSZ, TAG);
//		if (!imageBuffer)
//		{
//#ifdef _DEBUG 
//			DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//			* status = STATUS_FAILED_BUFFER_ALLOC;
//			return NULL;
//		}
//
//
//		Read(imageBuffer, BaseAddr, bufferSZ);
//	}
//	else
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//		* status = STATUS_FAILED_IMAGE_SIZE;
//		return NULL;
//	}
//
//#ifdef _DEBUG 
//	DbgPrint("[+]Operation Successfull\n");
//#endif
//
//	*status = STATUS_SUCCESS;
//	*szBuffer = bufferSZ;
//
//	return imageBuffer;
//}
//
//
//
//
//
//static ULONG Read_Write_File(IN PVOID baseAddress, IN WCHAR* DumpFolder, IN WCHAR* DumpName)
//{
//#ifdef _DEBUG 
//	DbgPrint("[+]Read_Write_File() Function Called\n");
//#endif
//
//
//	ULONG						  status = 0,
//							    szBuffer = 0;
//	PVOID				  imageBuffer = NULL,
//						  imageHeader = NULL;
//
//
//
//	imageBuffer = Write_To_Buffer(baseAddress, &szBuffer, &status);
//	if (status != STATUS_SUCCESS)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		return status;
//	}
//
//	imageHeader = imageBuffer;
//
//	/////////////////////////////////////////////////////////////////////////////////
//
//	IO_STATUS_BLOCK				  misc_sb = { 0 };
//	OBJECT_ATTRIBUTES		   dir_objatt = { 0 },
//		file_objatt = { 0 };
//	HANDLE					   file_Handle = NULL,
//		Dir_Handle = NULL;
//	UNICODE_STRING				 file_Dir = { 0 },
//		dump_File = { 0 };
//
//	///converting wchar to unicode
//	RtlInitUnicodeString(&file_Dir, DumpFolder);
//	RtlInitUnicodeString(&dump_File, DumpName);
//
//
//
//	InitializeObjectAttributes(&dir_objatt, &file_Dir, OBJ_KERNEL_HANDLE, NULL, NULL);
//
//	if (NT_SUCCESS(status = ZwCreateFile(&Dir_Handle, DELETE,
//		&dir_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_DIRECTORY, 0,
//		FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0)))
//	{
//
//		InitializeObjectAttributes(&file_objatt, &dump_File, OBJ_KERNEL_HANDLE, NULL, NULL);
//
//		if (NT_SUCCESS(status = ZwCreateFile(&file_Handle, GENERIC_ALL,
//			&file_objatt, &misc_sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
//			FILE_SUPERSEDE, FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
//		{
//			///writing to file
//			if (NT_SUCCESS(status = ZwWriteFile(
//				file_Handle, NULL, NULL, NULL, &misc_sb,
//				imageBuffer, szBuffer, NULL, NULL)))
//			{
//#ifdef _DEBUG 
//				DbgPrint("[+]Operation Successfull\n");
//#endif
//			}
//			else
//			{
//
//#ifdef _DEBUG 
//				DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//				ZwDeleteFile(&dir_objatt);
//				ZwDeleteFile(&file_objatt);
//				status = STATUS_FAILED_TO_WRITE;
//				goto end3;
//			}
//		}
//		else
//		{
//
//#ifdef _DEBUG 
//			DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//			status = STATUS_FAILED_TO_CREATE_FILE;
//			goto end2;
//		}
//	}
//	else
//	{
//
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation Unsuccessfull\n");
//#endif
//
//		status = STATUS_FAILED_TO_CREATE_DIR;
//		goto end1;
//	}
//
//	end3:
//	ZwClose(file_Handle);
//	end2:
//	ZwClose(Dir_Handle);
//	end1:
//	ExFreePool(imageHeader);
//
//	return status;
//}
//
//
//
//
//void Advanced_Process_Dump(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
//{
//#ifdef _DEBUG 
//	DbgPrint("[+]Advanced_ProcessDump() Function Called\n");
//#endif
//	if (Create)
//	{
//		UNREFERENCED_PARAMETER(ParentId);
//		WCHAR*				    ProcName = { 0 };
//		PEPROCESS				   target = NULL;
//		PUNICODE_STRING		  processName = NULL;
//		PVOID			   ProcNameHeader = NULL;
//
//		ProcName = Check_Exe(AdvDmpTarget.Buffer, processName->Buffer, processName->Length);
//		ProcNameHeader = ProcName;
//		
//		if (RSHasher(ProcName, AdvDmpTarget.Buffer))
//		{
//			KAPC_STATE				   state = { 0 };
//			PVOID					 BaseAddr = NULL,
//								   EntryPoint = NULL;
//			ULONG						  status = 1;
//			HANDLE					  hThread = NULL;
//
//
//
//			PsLookupProcessByProcessId(ProcessId, &target);
//			SeLocateProcessImageName(target, &processName);
//
//			if (NT_SUCCESS(status = PsSuspendProcess(ProcessId)))
//			{
//#ifdef _DEBUG 
//				DbgPrint("[!]Failed To Suspend Process With ERROR : %lu\n", status);
//#endif
//				ExFreePool(ProcNameHeader);
//				ObDereferenceObject(target);
//				return;
//			}
//
//			KeStackAttachProcess(target, &state);
//
//			EntryPoint = Ldr_Data(ProcName, target, &BaseAddr, &status);
//			if (status != STATUS_SUCCESS)
//			{
//#ifdef _DEBUG 
//				DbgPrint("[!]Operation Unsuccessfull With ERROR : %lu\n", status);
//#endif
//
//				KeUnstackDetachProcess(&state);
//				ExFreePool(ProcNameHeader);
//				ObDereferenceObject(target);
//				return;
//			}
//
//			hThread = PsGetCurrentThreadId();
//
//			if (!NT_SUCCESS(status = SetHardwareBreakingPnt(hThread, EntryPoint, Dr0)))
//			{
//#ifdef _DEBUG 
//				DbgPrint("[!]Operation Unsuccessfull With ERROR : %lu\n", status);
//#endif
//
//				KeUnstackDetachProcess(&state);
//				ExFreePool(ProcNameHeader);
//				ObDereferenceObject(target);
//				return;
//			}
//
//
//			if (NT_SUCCESS(status = PsResumeProcess(ProcessId)))
//			{
//#ifdef _DEBUG 
//				DbgPrint("[!]Failed To Resume Process With ERROR : %lu\n", status);
//#endif
//
//				KeUnstackDetachProcess(&state);
//				ExFreePool(ProcNameHeader);
//				ObDereferenceObject(target);
//				return;
//			}
//
//
//			if (!NT_SUCCESS(status = Read_Write_File(BaseAddr, AvdDumpFldr.Buffer, AvdDumpName.Buffer)))
//			{
//#ifdef _DEBUG 
//				DbgPrint("[!]Operation Unsuccessfull With ERROR : %lu\n", status);
//#endif
//
//				KeUnstackDetachProcess(&state);
//				ExFreePool(ProcNameHeader);
//				ObDereferenceObject(target);
//				return;
//			}
//			else
//			{
//#ifdef _DEBUG 
//				DbgPrint("[+]Operation Successfull\n");
//#endif
//				HANDLE Destroy = ZwCurrentProcess();
//				KeUnstackDetachProcess(&state);
//				ExFreePool(ProcNameHeader);
//				ZwTerminateProcess(Destroy, STATUS_SUCCESS);
//				ObDereferenceObject(target);
//				return;
//			}
//		}
//		else
//		{
//#ifdef _DEBUG 
//			DbgPrint("[!]Incorrect Application\n");
//#endif
//		}
//	}
//}