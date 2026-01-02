#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );

/*
Crystal Palace supports 'dynamic function resolution' using the MODULE$Function pattern for referencing Windows APIs.
The implementation in Crystal Palace is quite unique though, and must be paired with a resolve function.
This function is responsible for returning a pointer to the API in question.
You can implement this in anyway that you like, but a quick and easy method is to use functions provided by Crystal Palace's standard library.
*/
FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    /*
    findModuleByHash gets a reference to the Process Environment Block (PEB) and walks the process'
    InMemoryOrderModuleList until it finds the target module. findFunctionByHash then walks the
    Export Address Table (EAT) of a specific module until it finds the target function.
    */
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
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
