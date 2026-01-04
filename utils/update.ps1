param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# ASCII format string:
#   %c%c%c%c%c%c%c%c%cMSSE-%d-server
$searchBytes = @(0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x4D, 0x53, 0x53, 0x45, 0x2D, 0x25, 0x64, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72)
$replaceBytes = @(0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x25, 0x63, 0x4D, 0x53, 0x53, 0x45, 0x2D, 0x25, 0x64, 0x2D, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72)

# 48 89 C2      mov     rdx, rax               ; rdx = rax
# 83 E2 03      and     edx, 3                 ; rdx = rdx & 3   (index mod 4)
# 41 8A 14 14   mov     dl, byte ptr [r12+rdx] ; dl = key[rdx]
# 32 54 05 00   xor     dl, byte ptr [rbp+rax] ; dl ^= data[rax]
# 88 14 03      mov     byte ptr [rbx+rax], dl ; output[rax] = dl
# 48 FF C0      inc     rax                    ; rax++
# EB ??         jmp     short <loop_start>
#
# The first 3 bytes can be also represented as: 48 8B D0
#   48 → REX.W
#   8B → MOV r64, r/m64
#   D0 → ModRM (rdx ← rax)
#$searchBytes = @(0x48, 0x89, 0xC2, 0x83, 0xE2, 0x03, 0x41, 0x8A, 0x14, 0x14, 0x32, 0x54, 0x05, 0x00, 0x88, 0x14, 0x03, 0x48, 0xFF, 0xC0, 0xEB)
#$replaceBytes = @(0x48, 0x8B, 0xD0, 0x83, 0xE2, 0x03, 0x41, 0x8A, 0x14, 0x14, 0x32, 0x54, 0x05, 0x00, 0x88, 0x14, 0x03, 0x48, 0xFF, 0xC0, 0xEB)

# Read the file as bytes
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)

# Search and replace
$modified = $false
for ($i = 0; $i -le ($fileBytes.Length - $searchBytes.Length); $i++) {
    $match = $true
    for ($j = 0; $j -lt $searchBytes.Length; $j++) {
        if ($fileBytes[$i + $j] -ne $searchBytes[$j]) {
            $match = $false
            break
        }
    }
    
    if ($match) {
        for ($j = 0; $j -lt $replaceBytes.Length; $j++) {
            $fileBytes[$i + $j] = $replaceBytes[$j]
        }
        $modified = $true
        Write-Host "Replaced bytes at offset $i"
    }
}

# Write back to file if modified
if ($modified) {
    [System.IO.File]::WriteAllBytes($FilePath, $fileBytes)
    Write-Host "File updated successfully."
} else {
    Write-Host "No matching bytes found."
}