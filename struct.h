typedef struct _HANDLEENTRY {
    PVOID   phead;
    PVOID   pOwner;
    BYTE    bType;
    BYTE    bFlags;
    WORD    wUniq;
} HANDLEENTRY, * PHANDLEENTRY;

typedef struct _SERVERINFO {
    WORD    wRIPFlags;
    WORD    wSRVIFlags;
    WORD    wRIPPID;
    WORD    wRIPError;
    ULONG   cHandleEntries;
} SERVERINFO, * PSERVERINFO;

typedef struct _SHAREDINFO {
    PSERVERINFO  psi;
    PHANDLEENTRY aheList;
    ULONG        HeEntrySize;
} SHAREDINFO, * PSHAREDINFO;


typedef struct _LARGE_STRING {
    ULONG Length;
    ULONG MaximumLength : 31;
    ULONG bAnsi : 1;
    PVOID Buffer;
} LARGE_STRING, * PLARGE_STRING;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
} PEB, * PPEB;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB
{
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
}TEB, * PTEB;

#define LENGTH_TAGWND 0x128
#define OFFSET_SPWNDPARENT_WIN7 0x58
#define OFFSET_STRNAME_WIN7 0xD8
#define OFFSET_CBWNDEXTRA_WIN7 0xE8
#define OFFSET_APCADDR_WIN7 0x50
#define OFFSET_APCEPROCESS_WIN7 0x20
#define OFFSET_SECTOKEN_WIN7 0x208
#define OFFSET_EPROCESSPID_WIN7 0x180
#define OFFSET_EPROCESSBLINK_WIN7 0x188