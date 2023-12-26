#include "Utility.h"
#include <intsafe.h>

static UINT32 RS_Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

BOOL RSHasher(IN PWCHAR String1, IN PWCHAR String2)
{
	int S1_Value = 0;
	int S2_Value = 0;

	for (int i = 0; i < wcslen(String1); i++)
	{
		S1_Value = String1[i] + RS_Sub(S1_Value, _SEED);
	}

	for (int i = 0; i < wcslen(String2); i++)
	{
		S2_Value = String2[i] + RS_Sub(S2_Value, _SEED);
	}

	if (S2_Value == S1_Value)
	{
		return TRUE;
	}


	return FALSE;
}


ULONG PE_Check(IN PVOID BaseAddr)
{
#ifdef _DEBUG 
	DbgPrint("[+]PE_Check() Function Called\n");
#endif

	PIMAGE_DOS_HEADER		p_idh = NULL;
	PIMAGE_NT_HEADERS		p_inh = NULL;
	ULONG					  status = 0;

	
	
	///making sure module is of proper PE format
	p_idh = (PIMAGE_DOS_HEADER)BaseAddr;
	if (p_idh->e_magic != IMAGE_DOS_SIG)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		status = STATUS_FAILED_EMAGIC;
		goto end;
	}


	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
	if (p_inh->Signature != IMAGE_NT_SIG)
	{
		
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		status = STATUS_FAILED_NT_SIG;
		goto end;
	}

	status = STATUS_SUCCESS;

#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

end:
	return status;
}



ULONG Fix_Headers(IN LPVOID BaseAddr)
{
#ifdef _DEBUG 
	DbgPrint("[+]Fix_Headers() Function Called\n");
#endif


	PIMAGE_DOS_HEADER		p_idh = NULL;
	PIMAGE_NT_HEADERS		p_inh = NULL;
	PIMAGE_SECTION_HEADER	p_ish = NULL;
	ULONG					  status = 0;

#define IMAGE_FIRST_SECTION(p_inh)                       \
	((PIMAGE_SECTION_HEADER)((ULONG_PTR)(p_inh)+			\
	 FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +		\
		((p_inh))->FileHeader.SizeOfOptionalHeader))


	///making sure module is of proper PE format
	p_idh = (PIMAGE_DOS_HEADER)BaseAddr;
	if (p_idh->e_magic != IMAGE_DOS_SIG)
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		status = STATUS_FAILED_EMAGIC;
		goto end;
	}


	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
	if (p_inh->Signature != IMAGE_NT_SIG)
	{

#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		status = STATUS_FAILED_NT_SIG;
		goto end;
	}


	p_ish = IMAGE_FIRST_SECTION(p_inh);
	if (p_ish)
	{
		for (int i = 0; i < p_inh->FileHeader.NumberOfSections; i++, p_ish++)
		{
			p_ish->PointerToRawData = p_ish->VirtualAddress;
			p_ish->SizeOfRawData = p_ish->Misc.VirtualSize;
		}
	}
	else
	{
		status = STATUS_FAILED_FIRST_SECTION;
		goto end;
	}

	DbgPrint("444\n");

	status = STATUS_SUCCESS;

#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

end:
	return status;

}






CLIENT_ID Process_ID(IN WCHAR* ProcName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_ID() Function Called\n");
#endif

	PSYSTEM_PROCESS_INFORMATION   pSpiEntry = NULL;
	ULONG							  szBuffer = 0;
	CLIENT_ID						   cID = { 0 };
	NTSTATUS						   status = -1;
	PVOID					     pSpiHeader = NULL;

	do
	{
		///calling to get buffer size
		status = ZwQuerySystemInformation(SystemProcessInformation, 0, szBuffer, &szBuffer);


		///allocating memory for real call
		pSpiEntry = ExAllocatePool2(POOL_FLAG_NON_PAGED, szBuffer, TAG);
		if (pSpiEntry)
		{
			///real call to get information
			status = ZwQuerySystemInformation(SystemProcessInformation, pSpiEntry, szBuffer, &szBuffer);
			
		}
		else
		{	
			cID.UniqueProcess = 0;
			cID.UniqueThread = 0;
			return cID;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	
	pSpiHeader = pSpiEntry;
	
	while (1)
	{
		///make sure there is something in buffer to compare
		if (pSpiEntry->ImageName.Buffer)
		{
			///comparing Process Names till We Get The One We Want
			if (RSHasher(ProcName, pSpiEntry->ImageName.Buffer))
			{	
				cID.UniqueProcess = pSpiEntry->UniqueProcessId;
				
				break;
			}
		}
		if (pSpiEntry->NextEntryOffset == 0) break;
		
		
		pSpiEntry = (PSYSTEM_PROCESS_INFORMATION)((UCHAR*)pSpiEntry + pSpiEntry->NextEntryOffset);
	}

	ExFreePoolWithTag(pSpiHeader, TAG);
	
	if (cID.UniqueProcess)
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
#endif	
		
		return cID;
	}

	

#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull\n");
#endif

	cID.UniqueProcess = 0;
	cID.UniqueThread = 0;
	return cID;
}


VOID Copy_Physical_Memory(PVOID Buffer, IN PVOID Source, IN SIZE_T szBuffer)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Physical() Function Called\n");
#endif

	MM_COPY_ADDRESS  p_Copy = { 0 };
	SIZE_T				  Bytes = 0;

	p_Copy.PhysicalAddress = MmGetPhysicalAddress(Source);
	
	
	KeEnterCriticalRegion();
	__try
	{
		MmCopyMemory(Buffer, p_Copy, szBuffer, MM_COPY_MEMORY_PHYSICAL, &Bytes);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation Unsuccessfull\n");
#endif

		Buffer = NULL;
	}
	KeLeaveCriticalRegion();
	

#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif


}


///could be used for custom get proc address
//static PVOID Get_Virtual_Info(PVOID BaseAddr, OUT PULONG VirtSize)
//{
//#ifdef _DEBUG 
//	DbgPrint("[+]Get_Virtual_Size() Function Called\n");
//#endif
//
//	NTSTATUS					  status;
//	PIMAGE_DOS_HEADER		p_idh = NULL;
//	PIMAGE_NT_HEADERS		p_inh = NULL;
//	PVOID				virt_Addr = NULL,
//		result = NULL;
//	ULONG                  virt_Size = 0;
//	__int64				   temp_Base = 0;
//
//
//	KeEnterCriticalRegion();
//
//	///making sure module is of proper PE format
//	p_idh = (PIMAGE_DOS_HEADER)BaseAddr;
//	if (p_idh->e_magic != IMAGE_DOS_SIG)
//	{
//#ifdef _DEBUG
//		DbgPrint("[!]Failed e_Magic Check\n");
//#endif
//		status = STATUS_UNSuccessfull;
//		goto end;
//	}
//
//	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
//	if (p_inh->Signature != IMAGE_NT_SIG)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Failed e_lfanew Check\n");
//#endif
//		status = STATUS_UNSuccessfull;
//		goto end;
//	}
//
//	///main operation
//	virt_Addr = C_PTR(p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
//	virt_Size = (ULONG)p_inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//	if (virt_Addr == 0)
//	{
//#ifdef _DEBUG 
//		DbgPrint("[!]Unable To Query Virtual Information\n");
//#endif
//		status = STATUS_UNSuccessfull;
//	}
//
//end:
//	{
//		KeLeaveCriticalRegion();
//#ifdef _DEBUG 
//		DbgPrint("[!]Operation UnSuccessfull\n");
//#endif
//	}
//	return NULL;
//}