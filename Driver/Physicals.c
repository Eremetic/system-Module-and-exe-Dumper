#include"Physicals.h"

PEB64 Read_PEB(IN PVOID Source)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Physical() Function Called\n");
#endif

	MM_COPY_ADDRESS  p_Copy = { 0 };
	SIZE_T				  Bytes = 0;
	PEB64			    Peb = { 0 };
	PVOID			 pBuffer = NULL;
	SIZE_T szBuffer = sizeof(PEB64);

	
	p_Copy.PhysicalAddress = MmGetPhysicalAddress(Source);

	pBuffer = ExAllocatePool2(NonPagedPool, szBuffer, 0);

	KeEnterCriticalRegion();
	__try
	{
		MmCopyMemory(pBuffer, p_Copy, szBuffer, MM_COPY_MEMORY_PHYSICAL, &Bytes);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		pBuffer = NULL;
	}
	KeLeaveCriticalRegion();
	__try
	{
		RtlCopyMemory(&Peb, pBuffer, szBuffer);
	}
	__finally
	{
		ExFreePool(pBuffer);
	}


#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

	return Peb;
}




KLDR_DATA_TABLE_ENTRY Read_KLDR(IN PVOID Source)
{
#ifdef _DEBUG 
	DbgPrint("[+]Read_Physical() Function Called\n");
#endif

	MM_COPY_ADDRESS					 p_Copy = { 0 };
	SIZE_T								  Bytes = 0;
	KLDR_DATA_TABLE_ENTRY			   KLdr = { 0 };
	PVOID							 pBuffer = NULL;
	SIZE_T szBuffer = sizeof(KLDR_DATA_TABLE_ENTRY);


	p_Copy.PhysicalAddress = MmGetPhysicalAddress(Source);

	pBuffer = ExAllocatePool2(NonPagedPool, szBuffer, 0);

	KeEnterCriticalRegion();
	__try
	{
		MmCopyMemory(pBuffer, p_Copy, szBuffer, MM_COPY_MEMORY_PHYSICAL, &Bytes);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
#ifdef _DEBUG 
		DbgPrint("[!]Operation UnSuccessfull\n");
#endif

		pBuffer = NULL;
	}
	KeLeaveCriticalRegion();
	__try
	{
		RtlCopyMemory(&KLdr, pBuffer, szBuffer);
	}
	__finally
	{
		ExFreePool(pBuffer);
	}


#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

	return KLdr;
}