#include "FunctionPtrs.h"
#include "Utility.h"




static PVOID Dll_Base(IN const wchar_t* ModuleName);

static PVOID Function_Addr(IN PVOID dllBase, IN LPCSTR procName);



PVOID Function_PTR(IN const wchar_t* ModuleName, IN LPCSTR ProcName)
{
    PVOID       dllBase = Dll_Base(ModuleName),
        funcPtr = Function_Addr(dllBase, ProcName);

    return funcPtr;
}




static PVOID Dll_Base(IN const wchar_t* ModuleName)
{
    PVOID Base = NULL;
    ULONG64 dllBase = 0;
    PPEB64 peb = (PPEB64)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY64 ldrEntry = NULL, result = NULL;


    PPEB_LDR_DATA64 pLdr = (PPEB_LDR_DATA64)peb->Ldr;

    ldrEntry = (PLDR_DATA_TABLE_ENTRY64)pLdr->InMemoryOrderModuleList.Flink;

    do
    {
        if (ldrEntry->FullDllName.Buffer)
        {

            if (RSHasher((PWCHAR)ModuleName, ldrEntry->FullDllName.Buffer))
            {
                result = CONTAINING_RECORD(ldrEntry, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

                break;
            }
        }

        ldrEntry = *(PLDR_DATA_TABLE_ENTRY64*)(ldrEntry);

    } while (ldrEntry);



    return result->DllBase;
}




static PVOID Function_Addr(IN PVOID dllBase, IN LPCSTR procName)
{
    LPBYTE         pBase = ((LPBYTE)dllBase);
    PVOID                      result = NULL;
    PIMAGE_DOS_HEADER      dos_Header = NULL;
    PIMAGE_NT_HEADERS64     nt_Header = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDir = NULL;

    dos_Header = (PIMAGE_DOS_HEADER)dllBase;
    if (dos_Header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    nt_Header = (PIMAGE_NT_HEADERS64)(pBase + dos_Header->e_lfanew);
    if (nt_Header->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    if ((nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) == 0)
    {
        return NULL;
    }

    exportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + nt_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    
    PDWORD         nameArray = (PDWORD)(pBase + exportDir->AddressOfNames);
    PWORD      ordinal = (PWORD)(pBase + exportDir->AddressOfNameOrdinals);
    PDWORD  addressArray = (PDWORD)(pBase + exportDir->AddressOfFunctions);

    for (auto i = 0; i < exportDir->NumberOfFunctions; i++)
    {
        char* name = (char*)(pBase + nameArray[i]);
        if (name)
        {
            if (strcmp(procName, name) == 0)
            {
                result = C_PTR(((ULONG64)dllBase + addressArray[ordinal[i]]));
                return result;
            }
        }
    }
    return NULL;
}


