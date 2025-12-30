typedef struct {
    PVOID gate;
    DWORD ssn;
} SYSCALL;

BOOL resolve_syscall ( SYSCALL * syscall, PVOID ntdll, PVOID fn );
void prepare_syscall ( );
NTSTATUS do_syscall  ( );