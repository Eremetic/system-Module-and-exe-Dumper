#pragma once
#include "Globals.h"
#include "ProcessDump.h"


PEB64 Read_PEB(IN PVOID Source);

KLDR_DATA_TABLE_ENTRY Read_KLDR(IN PVOID Source);