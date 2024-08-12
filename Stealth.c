#include "Stealth.h"

#pragma warning(suppress : 4996)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

DWORD GetProcessPID(LPWSTR name) {
    PSYSTEM_PROCESS_INFORMATION spi;
    ULONG Length=0;
    DWORD processID=0;
    
    while (TRUE) {
        if (NtQuerySystemInformation(5, NULL, NULL, &Length) != STATUS_INFO_LENGTH_MISMATCH)
            continue;

        spi = VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (spi == NULL)
            continue;
       
        if (NT_SUCCESS(NtQuerySystemInformation(5, spi, Length, &Length)))
            break;

        VirtualFree(spi,0, MEM_RELEASE);
    }

    //PSYSTEM_PROCESS_INFORMATION temp = spi;
    spi = (ULONGLONG)spi + spi->NextEntryOffset;
    while (TRUE)
    {
        if (wcsicmp(spi->ImageName.Buffer, name)==0) {
            processID = spi->UniqueProcessId;
            break;
        }
        if (spi->NextEntryOffset == 0)
            break;
        
        spi = (ULONGLONG)spi + spi->NextEntryOffset;
    }


    //VirtualFree(temp, Length, MEM_DECOMMIT);
    //VirtualFree(temp, 0, MEM_RELEASE);
    return processID;
}


void UnHook(LPWSTR Target, LPCSTR Func){
    int size;
    HANDLE Process;
    PVOID FuncAddress;
    PVOID Function = GetProcAddress(GetModuleHandleA("ntdll.dll"), Func);
    BYTE* ByteFunctionCode;
    DWORD processId = GetProcessPID(Target);
    ULONGLONG CC = 0xCCCCCCCCCCCCCCCC;
    int Old;
    FuncAddress = (ULONGLONG)Function;

    printf("UnHook Function: %s\n", Func);

    printf("PID: %d\n", processId);
    printf("Function Address: %p\n", Function);
    Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (Process == NULL) {
        printf("OpenProcess Errror %x", GetLastError());
        return 0;
    }

    for (size = 0;; size++) {
        if (memcmp((ULONGLONG)FuncAddress + size, &CC, 8) == 0) {
            break;
        }
    }

    ByteFunctionCode = (BYTE*)malloc(size);
    
    memcpy_s(ByteFunctionCode, size, FuncAddress, size);

    if (!VirtualProtectEx(Process, FuncAddress, size, PAGE_EXECUTE_READWRITE, &Old)) {
        printf("VirtualProtectEx Errror %x", GetLastError());
        return 0;
    }

    if(!WriteProcessMemory(Process, FuncAddress, ByteFunctionCode, size, NULL)) {
        printf("WriteProcessMemory Errror %x", GetLastError());
        return 0;
    }
    if (!VirtualProtectEx(Process, FuncAddress, size, Old, &Old)) {
        printf("VirtualProtectEx Errror %x", GetLastError());
        return 0;
    }

    printf("SUCCSUC UnHook!\n");
}
