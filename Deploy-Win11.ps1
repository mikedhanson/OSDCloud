[CmdletBinding()]
param()
$ScriptName = 'Michael.Hanson.dev'
$ScriptVersion = '1.0.0'

#region Initialize
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore

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

#region Transport Layer Security (TLS) 1.2
Write-Host -ForegroundColor Green "[+] Transport Layer Security (TLS) 1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion


#region WinPE
if ($WindowsPhase -eq 'WinPE') {
    #Process OSDCloud startup and load Azure KeyVault dependencies
    Invoke-Expression -Command (Invoke-RestMethod -Uri functions.osdcloud.com)
    osdcloud-StartWinPE -OSDCloud #-KeyVault
    
    Write-Host -ForegroundColor Cyan "To start a new PowerShell session, type 'start powershell' and press enter"
    Write-Host -ForegroundColor Cyan "Start-OSDCloud, Start-OSDCloudGUI, or Start-OSDCloudAzure, can be run in the new PowerShell window"

        #Set OSDCloud Vars
    $Global:MyOSDCloud = [ordered]@{
        Restart               = [bool]$False
        RecoveryPartition     = [bool]$true
        OEMActivation         = [bool]$True
        WindowsUpdate         = [bool]$true
        WindowsUpdateDrivers  = [bool]$true
        WindowsDefenderUpdate = [bool]$true
        SetTimeZone           = [bool]$true
        ClearDiskConfirm      = [bool]$False
        ShutdownSetupComplete = [bool]$false
        SyncMSUpCatDriverUSB  = [bool]$true
        CheckSHA1             = [bool]$true
    }

    # cmdlet from osdCloud
    if (Test-HPIASupport) {
        Write-Host "Detected HP Device, Enabling HPIA, HP BIOS and HP TPM Updates"
        #$Global:MyOSDCloud.DevMode = [bool]$True
        $Global:MyOSDCloud.HPTPMUpdate = [bool]$True
        if ($Product -ne '83B2' -and $Model -notmatch "zbook") {
            $Global:MyOSDCloud.HPIAALL = [bool]$true
        }

        #{$Global:MyOSDCloud.HPIAALL = [bool]$true}

        $Global:MyOSDCloud.HPBIOSUpdate = [bool]$true

        #$Global:MyOSDCloud.HPCMSLDriverPackLatest = [bool]$true #In Test 
        #Set HP BIOS Settings to what I want:

        Write-Host "Setting HP BIOS Settings"

        #iex (irm https://raw.githubuserconten.tcom/gwblok/garytown/master/OSD/CloudOSD/Manage-HPBiosSettings.ps1)
        #Manage-HPBiosSettings -SetSettings

    }


    #Launch OSDCloud
    Write-Host "Starting OSDCloud" -ForegroundColor Green
    write-host "Start-OSDCloud -OSName $OSName -OSEdition $OSEdition -OSActivation $OSActivation -OSLanguage $OSLanguage"

    Start-OSDCloud -OSName $OSName -OSEdition $OSEdition -OSActivation $OSActivation -OSLanguage $OSLanguage

    write-host "OSDCloud Complete" -ForegroundColor Green

    #Reboot?

    
    #Stop the startup Transcript.  OSDCloud will create its own
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Specialize
if ($WindowsPhase -eq 'Specialize') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region AuditMode
if ($WindowsPhase -eq 'AuditMode') {
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region OOBE
if ($WindowsPhase -eq 'OOBE') {
    #Load everything needed to run AutoPilot and Azure KeyVault
    #osdcloud-StartOOBE -Display -Language -DateTime -Autopilot -KeyVault -InstallWinGet -WinGetUpgrade -WinGetPwsh
        
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion

#region Windows
if ($WindowsPhase -eq 'Windows') {
    #Load OSD and Azure stuff
    $null = Stop-Transcript -ErrorAction Ignore
}
#endregion
