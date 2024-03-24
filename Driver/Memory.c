#include "Memory.h"
#include "Utility.h"


#define Map(a, b, c , d)   Map_Physical_2_Virtual(a, b, c, d)
#define Unmap(a, b)         Unmap_Physical_From_Virtual(a, b) 
#define Read(a, b, c, d)		 Read_Mapped_Data(a, b, c, d)




PVOID Process_Base(IN PEPROCESS process, OUT PULONG status)
{

	if (!process) return 0;

	PVOID baseAddr = NULL;

	baseAddr = PsGetProcessSectionBaseAddress(process);
	if (!baseAddr)
	{
		* status = STATUS_FAILED_BASE_ADDR;
		return NULL;
	}

	return baseAddr;
}




ULONG_PTR Process_CR3(IN PEPROCESS process, OUT PULONG status)
{

	if (!process) return 0;

	ULONG_PTR Cr3 = 0;

	Cr3 = (ULONG_PTR) * (PULONG_PTR*)((ULONG_PTR)process + DirectoryTableBase);


	if (Cr3 == 0)
	{
		* status = STATUS_FAILED_CR3;
		return 0;
	}

	return Cr3;
}

PEPROCESS Process(IN WCHAR* ProcName)
{
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

		szBuffer += 0x60;
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

	return NULL;
}




ULONG_PTR VtoP(IN VIRTUAL_ADDRESS Linear, IN ULONG_PTR CR3, OUT PULONG status)
{ 

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
		*status = v2p_Status;
		goto cleanup;
	}
	Unmap(virtualAddress, &v2p_Status);
	if (v2p_Status != STATUS_SUCCESS)
	{
		*status = v2p_Status;
		goto cleanup;
	}

	if (pml4.Entry.value == 0 || pml4.Entry.Bit.Valid == 0)
	{
		*status = STATUS_FAILED_PML4E;
		goto cleanup;
	}
#ifdef _DEBUG 
	DbgPrint("pml4e: 0x%llx\n", pml4.Entry.value);
#endif	
	

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
		*status = STATUS_FAILED_PDPTE;
		goto cleanup;
	}
#ifdef _DEBUG 
	DbgPrint("pdp : 0x%llx\n", pdp.Entry.value);
#endif	

	if (pdp.Entry.Bit.LargePage == 1)
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
			*status = STATUS_FAILED_LRGPDPTE;
			goto cleanup;
		}
#ifdef _DEBUG 
		DbgPrint("Large pdp : 0x%llx\n", pdp.lrg_Entry.value);
#endif	
		
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
		*status = STATUS_FAILED_PDE;
		goto cleanup;
	}
#ifdef _DEBUG 
	DbgPrint("pd : 0x%llx\n", pd.Entry.value);
#endif	
	

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
			*status = STATUS_FAILED_LRGPDE;
			goto cleanup;
		}
#ifdef _DEBUG 
		DbgPrint("Large pd : 0x%llx\n", pd.lrg_Entry.value);
#endif	
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
#ifdef _DEBUG 
		DbgPrint("Failed PTE : 0x%llx\n", pt.Entry.value);
#endif		
		*status = STATUS_FAILED_PTE;
		goto cleanup;
	}
	physAddr = ((pt.Entry.Bit.PageFrameNumber << PAGE_SHIFT) + Linear.Bit.offset);

#ifdef _DEBUG 
	DbgPrint("physical address : 0x%llx\n", physAddr);
#endif	
	

	* status = STATUS_SUCCESS;
	return physAddr;

cleanup:
	return 0;
}




VOID Read_Process_Memory(_Inout_ PUCHAR pBuffer, IN VIRTUAL_ADDRESS linear,
	IN SIZE_T length, IN ULONG_PTR DirectoryTableBase, OUT PULONG status)
{
	if (!linear.pValue) return;

	ULONG			   read_Status = 1;
	ULONG_PTR      physicalAddress = 0;
	PUCHAR			virtualAddress = 0;

	

	physicalAddress = VtoP(linear, DirectoryTableBase, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto end;
	}

	Map(&virtualAddress, physicalAddress, length, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto end;
	}

	Read(pBuffer, virtualAddress, length, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto end;
	}

	Unmap(virtualAddress, &read_Status);
	if (read_Status != STATUS_SUCCESS)
	{
		*status = read_Status;
		goto end;
	}

	*status = STATUS_SUCCESS;

	return;

end:
	return;
}