x64:
    load "bin/services.x64.o"
        merge

    mergelib "../libtcg.x64.zip"

    dfr "resolve" "strings" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"
