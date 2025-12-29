#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );

/* patch function pointers in */
__typeof__ ( GetModuleHandle ) * get_module_handle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress )  * get_proc_address  __attribute__ ( ( section ( ".text" ) ) );

/**
 * This function is used to locate functions in
 * modules that are loaded by default (K32 & NTDLL)
 */
FARPROC resolve ( char * mod_name, char * func_name )
{
    HANDLE module = get_module_handle ( mod_name );
    return get_proc_address ( module, func_name );
}

/**
 * This function is used to load and/or locate functions
 * in modules that are not loaded by default.
 */
FARPROC resolve_ext ( char * mod_name, char * func_name )
{
    HANDLE module = KERNEL32$GetModuleHandleA ( mod_name );
    
    if ( module == NULL ) {
        module = LoadLibraryA ( mod_name );
    }
 
    return GetProcAddress ( module, func_name );
}
