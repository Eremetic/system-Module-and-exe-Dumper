#pragma once
#include "Globals.h"
#include "TokenHijack.h"
#include "ProcessDump.h"
#include "ModuleDump.h"
#include "UserModeBridge.h"
#include "Utility.h"


NTSTATUS DumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS DumpMod(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS Hijack(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS Get_Base_Addr(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);