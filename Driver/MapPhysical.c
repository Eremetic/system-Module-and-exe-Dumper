#include "Memory.h"

#pragma warning( disable : 4047 )

VOID Map_Physical_2_Virtual(
	OUT PUCHAR* VirtualAddress,
	IN ULONG_PTR physicalAddress,
	IN ULONG_PTR length,
	OUT PULONG status)
{

	ULONG				map_Status = 1,
		busAddressSpace = 0;
	SIZE_T				   mapSize = 0;
	UNICODE_STRING      device = { 0 };
	HANDLE			   hSection = NULL;
	PVOID				 Object = NULL;
	PUCHAR			virtualBase = NULL;
	OBJECT_ATTRIBUTES   objAtt = { 0 };
	PHYSICAL_ADDRESS  pAddr[3] = { 0 };
	BOOLEAN  halTranslateStart = FALSE,
		halTranslateEnd = FALSE;


	*VirtualAddress = 0;

	RtlInitUnicodeString(&device, L"\\Device\\PhysicalMemory");

	InitializeObjectAttributes(&objAtt, &device, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(map_Status = ZwOpenSection(&hSection, SECTION_ALL_ACCESS, &objAtt)))
	{
		*status = STATUS_FAILED_OPENSECTION;
		return;
	}

	if (!NT_SUCCESS(map_Status = ObReferenceObjectByHandle(
		hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &Object, NULL)))
	{
		*status = STATUS_FAILED_HANDLE_REF;
		return;
	}

	pAddr[0].QuadPart = physicalAddress;
	pAddr[1].QuadPart = pAddr[0].QuadPart + length;

	halTranslateStart = HalTranslateBusAddress(0, 0, pAddr[0], &busAddressSpace, &pAddr[0]);

	busAddressSpace = 0;

	halTranslateEnd = HalTranslateBusAddress(0, 0, pAddr[1], &busAddressSpace, &pAddr[1]);

	if (!halTranslateStart || !halTranslateEnd)
	{
		*status = STATUS_FAILED_HAL;
		goto cleanup;
	}

	pAddr[2] = pAddr[0];
	mapSize = (SIZE_T)pAddr[1].QuadPart - (SIZE_T)pAddr[0].QuadPart;

	if (!NT_SUCCESS(map_Status = ZwMapViewOfSection(
		hSection,
		ZwCurrentProcess(),
		&virtualBase,
		0L,
		mapSize,
		&pAddr[2],
		&mapSize,
		ViewShare,
		0,
		PAGE_READWRITE | PAGE_NOCACHE)))
	{
		*status = STATUS_FAILED_MAP;
		goto cleanup;
	}

	virtualBase += pAddr[0].QuadPart - pAddr[2].QuadPart;
	*VirtualAddress = virtualBase;


	ZwClose(hSection);
	*status = STATUS_SUCCESS;

	return;

cleanup:
	ZwClose(hSection);
}



VOID Unmap_Physical_From_Virtual(IN PUCHAR virtualAddress, OUT PULONG status)
{
	ULONG unmap_Status = 1;

	if (!NT_SUCCESS(unmap_Status = ZwUnmapViewOfSection(ZwCurrentProcess(), virtualAddress)))
	{
		* status = STATUS_FAILED_UNMAP;
		return;
	}

	* status = STATUS_SUCCESS;
}



VOID Read_Mapped_Data(PVOID pBuffer, IN PUCHAR virtualAddress, IN SIZE_T length, OUT PULONG status)
{
	ULONG		   rmd_Status = 1;
	MM_COPY_ADDRESS pCopy = { 0 };
	SIZE_T				bytes = 0;

	pCopy.VirtualAddress = virtualAddress;

	if (!NT_SUCCESS(rmd_Status = MmCopyMemory(pBuffer, pCopy, length, MM_COPY_MEMORY_VIRTUAL, &bytes)))
	{
#ifdef _DEBUG 		
		DbgPrint("MmCopyMemory Failed With ERROR : % lu, Number of Bytes Transfered : %llx of %llx\n", rmd_Status, bytes, length);
#endif

		* status = STATUS_MM_COPY_FAILED;
		return;
	}

	* status = STATUS_SUCCESS;
}