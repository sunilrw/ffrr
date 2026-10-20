# ==============================================================================
# PowerShell Integration Wrapper for FFRR
# ==============================================================================
function Invoke-FfrrSearch {
    param(
        [Parameter(Mandatory=$true)][string]$Find,
        [string]$Replace = "",
        [string]$Dir = ".",
        [string]$FileMask = "*.*",
        [switch]$Regex,
        [switch]$PreserveCase,
        [switch]$DryRun
    )
    $argsList = @("-f", $Find, "-d", $Dir, "-m", $FileMask, "-o", "json", "-q")
    if ($Replace -ne "") { $argsList += @("-r", $Replace) }
    if ($Regex) { $argsList += "-E" }
    if ($PreserveCase) { $argsList += "-P" }
    if ($DryRun) { $argsList += "--dry-run" }
    $raw = & ffrr @argsList
    return ($raw | ConvertFrom-Json)
}
