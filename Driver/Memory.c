#include "Memory.h"
#include "Utility.h"


#define Map(a, b, c , d)   Map_Physical_2_Virtual(a, b, c, d)
#define Unmap(a, b)     Unmap_Physical_From_Virtual(a, b) 
#define Read(a, b, c, d)   Read_Mapped_Data(a, b, c, d)




PVOID Process_Base(IN PEPROCESS process, OUT PULONG status)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_Base() Function Called\n");
#endif
	
	if (!process) return 0;

	PVOID baseAddr = NULL;
	
	baseAddr = PsGetProcessSectionBaseAddress(process);
	if (!baseAddr)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Process_Base() Operation Unsuccessfull\n");
#endif

		* status = STATUS_FAILED_BASE_ADDR;
		return NULL;
	}

#ifdef _DEBUG 
	DbgPrint("[+]Process_Base() Operation Successfull\n");
#endif

	return baseAddr;
}




ULONG_PTR Process_CR3(IN PEPROCESS process, OUT PULONG status)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process_CR3() Function Called\n");
#endif
	
	if (!process) return 0;
	
	ULONG_PTR Cr3 = 0;
	
	Cr3 = (ULONG_PTR)*(PULONG_PTR*)((ULONG_PTR)process + DirectoryTableBase);
	
	
	if (Cr3 == 0)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Process_CR3() Operation Unsuccessfull\n");
#endif

		* status = STATUS_FAILED_CR3;
		return 0;
	}

#ifdef _DEBUG 
	DbgPrint("[+]Process_CR3() Operation Successfull\n");
#endif

return Cr3;
}


PEPROCESS Process(IN WCHAR* ProcName)
{
#ifdef _DEBUG 
	DbgPrint("[+]Process() Function Called\n");
#endif

	PSYSTEM_PROCESS_INFORMATION   pSpiEntry = NULL;
	ULONG							  szBuffer = 0;
	CLIENT_ID						   cID = { 0 };
	NTSTATUS						   status = -1;
	PVOID					     pSpiHeader = NULL;
	PEPROCESS						 target = NULL;


	///sanity loop in case process opens while querying
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
			return NULL;
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

	ExFreePool(pSpiHeader);

	if (cID.UniqueProcess)
	{
		///Getting Eprocess
		if (NT_SUCCESS(status = PsLookupProcessByProcessId(cID.UniqueProcess, &target)))
		{
#ifdef _DEBUG 
			DbgPrint("[+]Process() Operation Successfull\n");
#endif	

			return target;
		}
	}

#ifdef _DEBUG 
	DbgPrint("[!]Process() Operation Unsuccessfull\n");
#endif


	return NULL;
}





ULONG_PTR VtoP(IN VIRTUAL_ADDRESS Linear , IN ULONG_PTR CR3, OUT PULONG status)
{
#ifdef _DEBUG 
	DbgPrint("[+]VtoP() Function Called\n");
#endif

	PML4				 pml4 = { 0 };
	PDP					  pdp = { 0 };
	PD					   pd = { 0 };
	PT					   pt = { 0 };
	ULONG_PTR			 physAddr = 0,
						   Offset = 0;
	PUCHAR		   virtualAddress = 0;
	ULONG			   v2p_Status = 1;


	Offset = (Linear.Bit.pml4_index * sizeof(PML4E));
	pml4.entry_Ptr = CR3;

	Map(&virtualAddress, (pml4.entry_Ptr + Offset), sizeof(PML4E), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Read(&pml4.Entry.value, virtualAddress, sizeof(PML4E), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		* status = v2p_Status;
		goto cleanup;
	}
	Unmap(virtualAddress, &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		* status = v2p_Status;
		goto cleanup;
	}
	

	if (pml4.Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
	{
		* status = STATUS_FAILED_PML4E;
		goto cleanup;
	}

	
	Offset = (Linear.Bit.pdp_index * sizeof(PDPE));
	pdp.entry_Ptr = (pml4.Entry.Bit.PageFrameNumber << PAGE_SHIFT);

	Map(&virtualAddress, (pdp.entry_Ptr + Offset), sizeof(PDPE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Read(&pdp.Entry.value, virtualAddress, sizeof(PDPE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Unmap(virtualAddress, &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}

	
	if (pdp.Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
	{
		* status = STATUS_FAILED_PDPTE;
		goto cleanup;
	}
	if(pdp.Entry.Bit.LargePage == 1)
	{	
		Offset = (Linear.Bit.pdp_index * sizeof(LRG_PDPE));
		
		Map(&virtualAddress, (pdp.entry_Ptr + Offset), sizeof(LRG_PDPE), &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}
		Read(&pdp.lrg_Entry.value, virtualAddress, sizeof(LRG_PDPE), &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}
		Unmap(virtualAddress, &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}
		
		pdp.Entry.value = 0;	

		if (pdp.lrg_Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
		{
			* status = STATUS_FAILED_LRGPDPTE;
			goto cleanup;
		}
		
	}


	Offset = (Linear.Bit.pd_index * sizeof(PDE));
	if (pdp.lrg_Entry.value != 0)
	{
		pd.entry_Ptr = (pdp.lrg_Entry.Bit.PageFrameNumber << PAGE_SHIFT);
	}
	else
		pd.entry_Ptr = (pdp.Entry.Bit.PageFrameNumber << PAGE_SHIFT);
	
	
	Map(&virtualAddress, (pd.entry_Ptr + Offset), sizeof(PDE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Read(&pd.Entry.value, virtualAddress, sizeof(PDE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Unmap(virtualAddress, &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}


	if (pd.Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
	{	
		* status = STATUS_FAILED_PDE;
		goto cleanup;
	}
	if (pd.Entry.Bit.LargePage == 1)
	{
		Offset = (Linear.Bit.pd_index * sizeof(LRG_PDE));

		Map(&virtualAddress, (pd.entry_Ptr + Offset), sizeof(LRG_PDE), &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}
		Read(&pd.lrg_Entry.value, virtualAddress, sizeof(LRG_PDE), &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}
		Unmap(virtualAddress, &v2p_Status);
		if (v2p_Status != STATUS_SUCCESS)
		{
			*status = v2p_Status;
			goto cleanup;
		}

		pd.Entry.value = 0;

		if (pd.lrg_Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
		{
			* status = STATUS_FAILED_LRGPDE;
			goto cleanup;
		}
	}


	Offset = (Linear.Bit.pt_index * sizeof(PTE));
	if (pd.lrg_Entry.value != 0)
	{
		pt.entry_Ptr = (pd.lrg_Entry.Bit.PageFrameNumber << PAGE_SHIFT);
	}
	else
		pt.entry_Ptr = (pd.Entry.Bit.PageFrameNumber << PAGE_SHIFT);
	

	Map(&virtualAddress, (pt.entry_Ptr + Offset), sizeof(PTE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Read(&pt.Entry.value, virtualAddress, sizeof(PTE), &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}
	Unmap(virtualAddress, &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}

	
	if (pt.Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
	{
		* status = STATUS_FAILED_PTE;
		goto cleanup;
	}
	
	physAddr = ((pt.Entry.Bit.PageFrameNumber << PAGE_SHIFT) + Linear.Bit.offset);

	
#ifdef _DEBUG 
	DbgPrint("[+]VtoP() Operation Successfull\n");
#endif

	* status = STATUS_SUCCESS;
	return physAddr;

cleanup:
#ifdef _DEBUG 
	DbgPrint("[!]VtoP() Operation Unsuccessfull\n");
#endif
	return 0;
}




VOID Read_Process_Memory(_Inout_ PUCHAR pBuffer, IN VIRTUAL_ADDRESS linear, 
	IN SIZE_T length, IN ULONG_PTR DirectoryTableBase, OUT PULONG status)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Process_Memoryy() Function Called\n");
#endif
	
	if (!linear.pValue) return;

	ULONG			   read_Status = 1;
	ULONG_PTR      physicalAddress = 0;
	PUCHAR			virtualAddress = 0;
	
	
	physicalAddress = VtoP(linear, DirectoryTableBase, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto cleanup;
	}

	Map(&virtualAddress, physicalAddress, length, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto cleanup;
	}

	Read(pBuffer, virtualAddress, length, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto cleanup;
	}

	Unmap(virtualAddress, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto cleanup;
	}
	
	*status = STATUS_SUCCESS;

#ifdef _DEBUG 
	DbgPrint("[+]Read_Process_Memory() Operation Successfull\n");
#endif

	return;

cleanup:
#ifdef _DEBUG 
	DbgPrint("[!]Read_Process_Memory() Operation Unsuccessfull\n");
#endif
	
}