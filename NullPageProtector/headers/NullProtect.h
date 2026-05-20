#pragma once

#include <ntifs.h>
#include "../headers/VADHeaders.h"
#define DRVTAG 'pn'
#define DrvName "NULLPageProtector-Driver:"

PMM_AVL_TABLE GetVadRoot(PEPROCESS Process);
PMMADDRESS_NODE FindVadContainingVpn(PMM_AVL_TABLE Root, ULONG_PTR Vpn);
NTSTATUS FreeNullPageIfMapped(PEPROCESS Process);
NTSTATUS CreateCustomVAD(PEPROCESS Process);
VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
VOID InsertVad(PMMVAD_LONG Vad, PEPROCESS CurrentProcess);
void DrvUnloadRoutine(PDRIVER_OBJECT DriverObject);