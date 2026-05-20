#pragma once
#if defined (_WIN64)

#define COMMIT_SIZE 51
#if ((COMMIT_SIZE + PAGE_SHIFT) < 63)
#error COMMIT_SIZE too small
#endif

#else
#define COMMIT_SIZE 19
#if ((COMMIT_SIZE + PAGE_SHIFT) < 31)
#error COMMIT_SIZE too small
#endif
#endif

#define MM_MAX_COMMIT (((ULONG_PTR) 1 << COMMIT_SIZE) - 1)
#define MM_NOACCESS           0x18   // NO_ACCESS, Guard_page, nocache.
typedef struct _MMVAD_FLAGS {
    ULONG_PTR CommitCharge : COMMIT_SIZE; // limits system to 4k pages or bigger!
    ULONG_PTR NoChange : 1;
    ULONG_PTR VadType : 3;
    ULONG_PTR MemCommit : 1;
    ULONG_PTR Protection : 5;
    ULONG_PTR Spare : 2;
    ULONG_PTR PrivateMemory : 1;    // used to tell VAD from VAD_SHORT
} MMVAD_FLAGS;
typedef struct _MMVAD_FLAGS2 {
    unsigned FileOffset : 24;       // number of 64k units into file
    unsigned SecNoChange : 1;       // set if SEC_NOCHANGE specified
    unsigned OneSecured : 1;        // set if u3 field is a range
    unsigned MultipleSecured : 1;   // set if u3 field is a list head
    unsigned ReadOnly : 1;          // protected as ReadOnly
    unsigned LongVad : 1;           // set if VAD is a long VAD
    unsigned ExtendableFile : 1;
    unsigned Inherit : 1;           //1 = ViewShare, 0 = ViewUnmap
    unsigned CopyOnWrite : 1;
} MMVAD_FLAGS2;
typedef struct _MMADDRESS_LIST {
    ULONG_PTR StartVpn;
    ULONG_PTR EndVpn;
} MMADDRESS_LIST, * PMMADDRESS_LIST;
typedef struct _MMVAD {
    union {
        LONG_PTR Balance : 2;
        struct _MMVAD* Parent;
    } u1;
    struct _MMVAD* LeftChild;
    struct _MMVAD* RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;

    union {
        ULONG_PTR LongFlags;
        MMVAD_FLAGS VadFlags;
    } u;
    PVOID ControlArea;
    PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
    union {
        ULONG LongFlags2;
        MMVAD_FLAGS2 VadFlags2;
    } u2;
} MMVAD, * PMMVAD;

typedef struct _MMVAD_LONG {
    union {
        LONG_PTR Balance : 2;
        struct _MMVAD* Parent;
    } u1;
    struct _MMVAD* LeftChild;
    struct _MMVAD* RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;

    union {
        ULONG_PTR LongFlags;
        MMVAD_FLAGS VadFlags;
    } u;
    PVOID ControlArea;
    PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
    union {
        ULONG LongFlags2;
        MMVAD_FLAGS2 VadFlags2;
    } u2;
    union {
        LIST_ENTRY List;
        MMADDRESS_LIST Secured;
    } u3;
    union {
        PVOID Banked;
        PVOID ExtendedInfo;
    } u4;
} MMVAD_LONG, * PMMVAD_LONG;


typedef struct _MMADDRESS_NODE {
    union {
        LONG_PTR Balance : 2;
        struct _MMADDRESS_NODE* Parent;
    } u1;
    struct _MMADDRESS_NODE* LeftChild;
    struct _MMADDRESS_NODE* RightChild;
    ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
} MMADDRESS_NODE, * PMMADDRESS_NODE;
typedef struct _MM_AVL_TABLE {
    MMADDRESS_NODE  BalancedRoot;
    ULONG_PTR DepthOfTree : 5;
    ULONG_PTR Unused : 3;
#if defined (_WIN64)
    ULONG_PTR NumberGenericTableElements : 56;
#else
    ULONG_PTR NumberGenericTableElements : 24;
#endif
    PVOID NodeHint;
    PVOID NodeFreeHint;
} MM_AVL_TABLE, * PMM_AVL_TABLE;