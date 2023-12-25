#pragma once
#include "Globals.h"
#include "TokenHijack.h"
#include "ProcessDump.h"
#include "ModuleDump.h"
#include "UserModeBridge.h"
#include "Utility.h"


NTSTATUS DumpProc(IN PIRP Irp);

NTSTATUS DumpMod(IN PIRP Irp);

NTSTATUS Hijack(IN PIRP Irp);

NTSTATUS Get_Base_Addr(IN PIRP Irp);