#include "../headers/NULLProtect.h"
// Retrieves the VAD root pointer based on the Windows version and architecture.
// Returns a pointer to the MM_AVL_TABLE for the process, or nullptr if not supported.
PMM_AVL_TABLE GetVadRoot(PEPROCESS Process)
{
    RTL_OSVERSIONINFOEXW Osi = { 0 };
    Osi.dwOSVersionInfoSize = sizeof(Osi);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&Osi);


#if defined(_WIN64)
    //Windows XP | Server 2003 SP2
    if (Osi.dwMajorVersion == 5 && Osi.dwMinorVersion == 2 && Osi.dwMajorVersion == 3790) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x398);
    }
    // Windows Vista | Server 2008 - (RTM SP1 SP2)
    if (Osi.dwMajorVersion == 6 && Osi.dwMinorVersion == 0 && (Osi.dwMajorVersion == 6000 || Osi.dwMajorVersion == 6001 || Osi.dwMajorVersion == 6002)) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x380);
    }
    // Windows 7 | Server 2008R2
    if (Osi.dwMajorVersion == 6 && Osi.dwMinorVersion == 1 && (Osi.dwMajorVersion == 7600 || Osi.dwMajorVersion == 7601)) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x448);
    }

    return nullptr;
#else
    // Windows XP SP3 (version 5.1.2600)
    if (Osi.dwMajorVersion == 5 && Osi.dwMinorVersion == 1 && Osi.dwBuildNumber == 2600) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x11c);
    }

    // Windows Server 2003 SP2 (version 5.2.3790)
    if (Osi.dwMajorVersion == 5 && Osi.dwMinorVersion == 2 && Osi.dwBuildNumber == 3790) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x250);
    }

    // Windows Vista and early Server 2008 (version 6.0.6000-6002)
    if (Osi.dwMajorVersion == 6 && Osi.dwMinorVersion == 0 &&
        (Osi.dwBuildNumber == 6000 || Osi.dwBuildNumber == 6001 || Osi.dwBuildNumber == 6002)) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x238);
    }

    // Windows 7 and early Server 2008 R2 (version 6.1.7600-7601)
    if (Osi.dwMajorVersion == 6 && Osi.dwMinorVersion == 1 &&
       (Osi.dwBuildNumber == 7600 || Osi.dwBuildNumber == 7601)) {
        return (PMM_AVL_TABLE)((PUCHAR)Process + 0x278);
    }

    return nullptr;
#endif
}

// Searches the VAD tree for a VAD containing the given virtual page number (VPN).
// Performs binary search on the AVL tree to find the appropriate node.
// Returns a pointer to the node if found, otherwise nullptr.
PMMADDRESS_NODE FindVadContainingVpn(PMM_AVL_TABLE Root, ULONG_PTR Vpn)
{
    if (!Root) {
        return nullptr;
    }

    PMMADDRESS_NODE Node = Root->BalancedRoot.RightChild;

    while (Node) {
        if (Vpn < Node->StartingVpn) {
            // Search in the left subtree
            Node = Node->LeftChild;
        }
        else if (Vpn > Node->EndingVpn) {
            // Search in the right subtree
            Node = Node->RightChild;
        }
        else {
            // VAD containing the VPN found
            return Node;
        }
    }

    return nullptr;
}

// Checks if the null page (VPN 0) is already mapped in the process address space.
// If it exists, frees the mapping using ZwFreeVirtualMemory within the process context.
// This ensures we can insert our custom null page VAD.
NTSTATUS FreeNullPageIfMapped(PEPROCESS Process)
{
    PMM_AVL_TABLE Root = GetVadRoot(Process);
    if (!Root) {
        return STATUS_NOT_SUPPORTED;
    }

    // Check if null page is already mapped
    if (!FindVadContainingVpn(Root, 0)) {
        return STATUS_NOT_FOUND;
    }

    // Attach to the target process to execute ZwFreeVirtualMemory in its context
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    PVOID BaseAddress = (PVOID)1;
    SIZE_T RegionSize = PAGE_SIZE;
    NTSTATUS Status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);

    KeUnstackDetachProcess(&ApcState);

    return Status;
}


// Creates and initializes a VAD for the null page protection.
// Allocates a MMVAD_LONG structure, configures it with appropriate flags,
// and inserts it into the process's VAD tree.
// Similar to MiCreatePebOrTeb() but for crafting a VAD in nullpage the target process address space.
NTSTATUS CreateCustomVAD(PEPROCESS Process)
{
    if (!Process) {
        return STATUS_INVALID_PARAMETER;
    }

    // First, attempt to free any existing null page mapping(VDM Process)
    NTSTATUS Status = FreeNullPageIfMapped(Process);
    if (Status != STATUS_SUCCESS && Status != STATUS_NOT_FOUND) {
        KdPrint((DrvName "Error freeing null page mapping (0x%08X)\n", Status));
        return Status;
    }

    // Allocate a VAD_LONG structure from non-paged pool
    PMMVAD_LONG NullPageVad = (PMMVAD_LONG)ExAllocatePoolWithTag(NonPagedPool, sizeof(MMVAD_LONG), DRVTAG);
    if (!NullPageVad) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(NullPageVad, sizeof(MMVAD_LONG));

    // Set the virtual address range to cover the null page
    NullPageVad->StartingVpn = 0;
    NullPageVad->EndingVpn = 0xffff >> PAGE_SHIFT;

    // Configure VAD flags
    NullPageVad->u.VadFlags.CommitCharge = MM_MAX_COMMIT;  // Prevent commit
    NullPageVad->u.VadFlags.MemCommit = FALSE;
    NullPageVad->u.VadFlags.PrivateMemory = TRUE;
    NullPageVad->u.VadFlags.Protection = MM_NOACCESS;      // No access protection
    NullPageVad->u.VadFlags.NoChange = TRUE;               // Mark as non-deleteable

    // Configure extended VAD flags
    NullPageVad->u2.VadFlags2.OneSecured = TRUE;
    NullPageVad->u2.VadFlags2.LongVad = TRUE;

    // Set the secured address range
    NullPageVad->u3.Secured.StartVpn = 0;
    NullPageVad->u3.Secured.EndVpn = 0xffff;

    // Insert the VAD into the process's VAD tree
    InsertVad(NullPageVad, Process);

    return STATUS_SUCCESS;
}

// Inserts a VAD into the AVL tree of the process without rebalancing.
// The tree will be automatically rebalanced by the kernel on subsequent VAD operations.
// Increments the NumberGenericTableElements counter.
VOID InsertVad(PMMVAD_LONG Vad, PEPROCESS CurrentProcess)
{
    ASSERT(Vad->EndingVpn >= Vad->StartingVpn);

#if defined(_WIN64)
    PMM_AVL_TABLE Root = GetVadRoot(CurrentProcess);
    if (!Root) {
        KdPrint((DrvName "Not Supported within os\n"));
        return;
    }
#else
    PMM_AVL_TABLE Root = GetVadRoot(CurrentProcess);
    if (!Root) {
        KdPrint((DrvName "Not Supported within os\n"));
        return;
    }
#endif

    // Update the NodeHint for faster future lookups
    Root->NodeHint = Vad;

    // Find the correct position to insert the new VAD
    PMMADDRESS_NODE ParentNode = &Root->BalancedRoot;
    PMMADDRESS_NODE Node = Root->BalancedRoot.RightChild;

    while (Node) {
        ParentNode = Node;
        if (Vad->StartingVpn < Node->StartingVpn) {
            Node = Node->LeftChild;
        }
        else {
            Node = Node->RightChild;
        }
    }

    // Initialize VAD node pointers and parent reference
    Vad->LeftChild = nullptr;
    Vad->RightChild = nullptr;
    Vad->u1.Parent = reinterpret_cast<PMMVAD>(ParentNode);
    Vad->u1.Balance = 0;

    // Link the VAD into the tree
    if (ParentNode == &Root->BalancedRoot) {
        Root->BalancedRoot.RightChild = (PMMADDRESS_NODE)Vad;
        if (Root->DepthOfTree == 0) {
            Root->DepthOfTree = 1;
        }
    }
    else if (Vad->StartingVpn < ParentNode->StartingVpn) {
        ParentNode->LeftChild = (PMMADDRESS_NODE)Vad;
    }
    else {
        ParentNode->RightChild = (PMMADDRESS_NODE)Vad;
    }

    // Increment the element counter in the AVL table
    Root->NumberGenericTableElements += 1;
}

// Called when a new process is created. Retrieves the process object and calls CreateCustomVAD
// to protect the null page in the new process's address space.
VOID CreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (!Create) {
        return;
    }

    // Lookup the process object by its process ID
    PEPROCESS Process = nullptr;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        KdPrint((DrvName "PsLookupProcessByProcessId failed (0x%08X)\n", Status));
        return;
    }

    // Create and insert the null page protection VAD
    Status = CreateCustomVAD(Process);
    if (!NT_SUCCESS(Status)) {
        KdPrint((DrvName "CreateCustomVAD failed (0x%08X)\n", Status));
    }

    // Release the reference acquired by PsLookupProcessByProcessId
    ObDereferenceObject(Process);
}