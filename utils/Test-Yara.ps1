$binaryPath = "C:\Tools\Payloads\beacon_x64_ck_121.exe"

$rulesDirs = @( 
  "$env:USERPROFILE\repos\protections-artifacts", 
  "$env:USERPROFILE\repos\defender2yara\rules\1.443.482.0\WinNT" 
)
$yaraPath = "C:\Tools\yara\yara64.exe"

foreach ($rulesDir in $rulesDirs) {
  if (-not (Test-Path $rulesDir)) {
    Write-Error "[!] Directory not found: $dir"
    continue
  }
  Write-Host "[*] ====================================================================================="
  Write-Host "[*] Testing rules in directory: $rulesDir"
  Write-Host "[*] ====================================================================================="
  Get-ChildItem $rulesDir -Recurse -File -Include *.yar,*.yara | ForEach-Object {
    & $yaraPath --print-strings --no-warnings --print-meta --print-module-data $_.FullName $binaryPath
    if ($LASTEXITCODE -ne 0) { "Broken: $($_.FullName)" }
  }
}
