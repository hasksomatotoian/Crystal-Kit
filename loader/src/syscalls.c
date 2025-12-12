#include <windows.h>
#include "syscalls.h"
#include "tcg.h"

#define STUB_SIZE 32

#define UP   -STUB_SIZE
#define DOWN  STUB_SIZE

#define DEREF8(ptr) * ( ( PBYTE ) ptr )

/**
 * Get the SSN and address of the syscall instruction
 * for a given Nt* function
 */
BOOL resolve_syscall ( SYSCALL * syscall, PVOID ntdll, PVOID fn )
{
    /* parse headers */
    IMAGE_DOS_HEADER       * dos_header = ( IMAGE_DOS_HEADER * ) ntdll;
    IMAGE_NT_HEADERS       * nt_headers = ( IMAGE_NT_HEADERS * ) ( ( PBYTE ) ntdll + dos_header->e_lfanew );
    IMAGE_EXPORT_DIRECTORY * export_dir = ( IMAGE_EXPORT_DIRECTORY * ) ( ( PBYTE ) ntdll + nt_headers->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );

    PDWORD addr_of_funcs = ( PDWORD ) ( ( PBYTE ) ntdll + export_dir->AddressOfFunctions );
    PWORD  addr_of_ords  = ( PWORD  ) ( ( PBYTE ) ntdll + export_dir->AddressOfNameOrdinals );

    /* init variables */
    PVOID stub     = fn, gate = NULL;
    DWORD ssn      = 0;
    WORD  idx_stub = 0, idx_name = 0;
    BOOL  hooked   = FALSE;

    for ( idx_stub = 0; idx_stub < STUB_SIZE; idx_stub++ )
    {
        /* e9 is a JMP */
        if ( DEREF8 ( stub + idx_stub ) == 0xe9 )
        {
            /* syscall is hooked */
            hooked = TRUE;
            break;
        }

        /* c3 is a RET */
        if ( DEREF8 ( stub + idx_stub ) == 0xc3 )
        {
            /* we've gone too far :( */
            return FALSE;
        }

        /*
        * 4c8bd1          mov     r10, rcx
        * b8??000000      mov     eax, ??
        */

        if ( DEREF8 ( stub + idx_stub     ) == 0x4c &&
             DEREF8 ( stub + idx_stub + 1 ) == 0x8b &&
             DEREF8 ( stub + idx_stub + 2 ) == 0xd1 &&
             DEREF8 ( stub + idx_stub + 3 ) == 0xb8 &&
             DEREF8 ( stub + idx_stub + 6 ) == 0x00 &&
             DEREF8 ( stub + idx_stub + 7 ) == 0x00 )
        {
            BYTE low  = DEREF8 ( stub + 4 + idx_stub );
            BYTE high = DEREF8 ( stub + 5 + idx_stub );

            ssn = ( high << 8 ) | low;

            break;
        }
    }

    if ( hooked )
    {
        /* check neighbouring functions */
        for ( idx_name = 1; idx_name <= export_dir->NumberOfFunctions; idx_name++ )
        {
            /* check next one down */
            if ( ( PBYTE ) stub + idx_name * DOWN < ( ( PBYTE ) ntdll + addr_of_funcs [ addr_of_ords [ export_dir->NumberOfFunctions - 1 ] ] ) )
            {
                if ( DEREF8 ( stub + idx_name * DOWN     ) == 0x4c &&
                     DEREF8 ( stub + 1 + idx_name * DOWN ) == 0x8b &&
                     DEREF8 ( stub + 2 + idx_name * DOWN ) == 0xd1 &&
                     DEREF8 ( stub + 3 + idx_name * DOWN ) == 0xb8 &&
                     DEREF8 ( stub + 6 + idx_name * DOWN ) == 0x00 &&
                     DEREF8 ( stub + 7 + idx_name * DOWN ) == 0x00 )
                {
                    BYTE low  = DEREF8 ( stub + 4 + idx_name * DOWN );
                    BYTE high = DEREF8 ( stub + 5 + idx_name * DOWN );
                    
                    ssn  = ( high << 8 ) | ( low - idx_name );
                    stub = ( PVOID ) ( ( PBYTE ) stub + idx_name * DOWN );

                    break;
                }
            }

            /* check next one up */
            if ( ( PBYTE ) stub + idx_name * UP > ( ( PBYTE ) ntdll + addr_of_funcs [ addr_of_ords [ 0 ] ] ) )
            {
                if ( DEREF8 ( stub + idx_name * UP     ) == 0x4c &&
                     DEREF8 ( stub + 1 + idx_name * UP ) == 0x8b &&
                     DEREF8 ( stub + 2 + idx_name * UP ) == 0xd1 &&
                     DEREF8 ( stub + 3 + idx_name * UP ) == 0xb8 &&
                     DEREF8 ( stub + 6 + idx_name * UP ) == 0x00 &&
                     DEREF8 ( stub + 7 + idx_name * UP ) == 0x00 )
                {
                    BYTE low  = DEREF8 ( stub + 4 + idx_name * UP );
                    BYTE high = DEREF8 ( stub + 5 + idx_name * UP );

                    ssn  = ( high << 8 ) | ( low + idx_name );
                    stub = ( PVOID ) ( ( PBYTE ) stub + idx_name * UP );

                    break;
                }
            }
        }
    }

    if ( stub && ssn )
    {
        /* search for the syscall; ret */
        for ( idx_stub = 0; idx_stub < STUB_SIZE; idx_stub++ )
        {
            /*
            * 0f05            syscall
            * c3              ret
            */

            if ( DEREF8 ( stub + idx_stub     ) == 0x0f &&
                 DEREF8 ( stub + idx_stub + 1 ) == 0x05 &&
                 DEREF8 ( stub + idx_stub + 2 ) == 0xc3 )
            {
                gate = ( LPVOID ) ( ( PBYTE ) stub + idx_stub );
                break;
            }
        }
    }

    if ( gate == NULL || ssn == 0 ) {
        return FALSE;
    }

    /* set syscall */
    syscall->gate = gate;
    syscall->ssn  = ssn;

    return TRUE;
}

/**
 * Prepare registers for syscall
 */
void __attribute__ ( ( naked ) ) prepare_syscall ( )
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "xor r11, r11;"
        "xor r10, r10;"
        "mov r11, rcx;"
        "mov r10, rdx;"
        "ret;"
        ".att_syntax prefix;"
    );
}

/**
 * Perform the syscall
 */
NTSTATUS __attribute__ ( ( naked ) ) do_syscall ( )
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "push r10;"
        "xor rax, rax;"
        "mov r10, rcx;"
        "mov eax, r11d;"
        "ret;"
        ".att_syntax prefix;"
    );
}
