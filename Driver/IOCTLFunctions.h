#pragma once
#include "Globals.h"


NTSTATUS DumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS DumpMod(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS Hijack(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);

NTSTATUS AdvDumpProc(IN PIO_STACK_LOCATION ourStack, IN PIRP Irp);