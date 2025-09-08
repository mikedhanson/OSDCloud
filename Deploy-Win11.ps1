[CmdletBinding()]
param(
    [string]$OSName      = "Windows 11 23H2 x64",
    [string]$OSEdition   = "Pro",
    [string]$OSActivation = "Retail",
    [string]$OSLanguage  = "en-us"
)

$ScriptName = 'Michaelhanson.dev'
$ScriptVersion = '1.0.2'

write-host "os name: $OSName"

read-host "Brfeak here" 

#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) #-ErrorAction Ignore

if ($env:SystemDrive -eq 'X:') {
    $WindowsPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') { $WindowsPhase = 'OOBE' }
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') { $WindowsPhase = 'Specialize' }
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') { $WindowsPhase = 'AuditMode' }
    else { $WindowsPhase = 'Windows' }
}

Write-Host -ForegroundColor Green "[+] $ScriptName $ScriptVersion ($WindowsPhase Phase)"

#region Admin Elevation
$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($isElevated) {
    Write-Host -ForegroundColor Green "[+] Running as $whoiam (Admin Elevated)"
}
else {
    Write-Host -ForegroundColor Red "[!] Running as $whoiam (NOT Admin Elevated)"
    Break
}
#endregion

#region TLS
Write-Host -ForegroundColor Green "[+] Enabling TLS 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    Invoke-Expression -Command (Invoke-RestMethod -Uri functions.osdcloud.com)
    osdcloud-StartWinPE -OSDCloud

    Write-Host -ForegroundColor Cyan "To start a new PowerShell session, type 'start powershell' and press enter"
    Write-Host -ForegroundColor Cyan "Start-OSDCloud, Start-OSDCloudGUI, or Start-OSDCloudAzure, can be run in the new PowerShell window"

    # Global Vars for OSDCloud
    $Global:MyOSDCloud = [ordered]@{
        Restart               = $false
        RecoveryPartition     = $true
        OEMActivation         = $true
        WindowsUpdate         = $true
        WindowsUpdateDrivers  = $true
        WindowsDefenderUpdate = $true
        SetTimeZone           = $true
        ClearDiskConfirm      = $false
        ShutdownSetupComplete = $false
        SyncMSUpCatDriverUSB  = $true
        CheckSHA1             = $true
    }

    if (Test-HPIASupport) {
        Write-Host "Detected HP Device, enabling HPIA + BIOS/TPM updates"
        $Global:MyOSDCloud.HPTPMUpdate = $true
        $Global:MyOSDCloud.HPIAALL     = $true
        $Global:MyOSDCloud.HPBIOSUpdate = $true
    }

    Write-Host "Starting OSDCloud with:" -ForegroundColor Green
    Write-Host "   OSName: $OSName"
    Write-Host "   OSEdition: $OSEdition"
    Write-Host "   OSActivation: $OSActivation"
    Write-Host "   OSLanguage: $OSLanguage"

    Start-OSDCloud -OSName $OSName -OSEdition $OSEdition -OSActivation $OSActivation -OSLanguage $OSLanguage

    Write-Host "OSDCloud Complete" -ForegroundColor Green
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') { $null = Stop-Transcript -ErrorAction Ignore }
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') { $null = Stop-Transcript -ErrorAction Ignore }
#endregion

#region OOBE
if ($WindowsPhase -eq 'OOBE') { $null = Stop-Transcript -ErrorAction Ignore }
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') { $null = Stop-Transcript -ErrorAction Ignore }
#endregion
