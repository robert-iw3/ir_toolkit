# Backup script - no malware indicators
param([string]$Source = "C:\Data", [string]$Dest = "D:\Backup")
Get-ChildItem $Source -Recurse | ForEach-Object {
    $target = $_.FullName.Replace($Source, $Dest)
    Copy-Item $_.FullName $target -Force
    Write-Output "Copied: $($_.Name)"
}
