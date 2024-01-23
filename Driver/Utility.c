#include "Utility.h"
#include "ModuleDump.h"
#include "Memory.h"

#define Read(a, b, c, d, e)		Read_Process_Memory(a, b, c, d, e)

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
		status = STATUS_FAILED_EMAGIC;
		goto end;
	}


	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
	if (p_inh->Signature != IMAGE_NT_SIG)
	{
		status = STATUS_FAILED_NT_SIG;
		goto end;
	}

	
#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

	return STATUS_SUCCESS;


end:
#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull\n");
#endif

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



	///making sure module is of proper PE format
	p_idh = (PIMAGE_DOS_HEADER)BaseAddr;
	if (p_idh->e_magic != IMAGE_DOS_SIG)
	{
		status = STATUS_FAILED_EMAGIC;
		goto end;
	}


	p_inh = (PIMAGE_NT_HEADERS)((LPBYTE)BaseAddr + p_idh->e_lfanew);
	if (p_inh->Signature != IMAGE_NT_SIG)
	{
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

#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull\n");
#endif

	return STATUS_SUCCESS;

end:
#ifdef _DEBUG 
	DbgPrint("[!]Operation Unsuccessfull\n");
#endif

	return status;

}


ULONG AlignValue(ULONG value, ULONG alignment)
{
	return ((value + alignment - 1) / alignment) * alignment;
}



