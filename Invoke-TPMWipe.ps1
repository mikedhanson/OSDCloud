<#
.SYNOPSIS
    Clears the TPM via CIM/WMI, logs all information, and uploads JSON results to Azure Blob Storage via REST API.
    Includes OSDCloud environmental initialization and testing mode.
#>
[CmdletBinding()]
param(
    [string]
    $EPMComputerName,

    [Parameter(Mandatory = $false)]
    [bool]
    $TestMode = $true,

    # --- Azure Blob Storage Configuration ---
    [Parameter(Mandatory = $false)]
    [string]
    $AzureStorageAccount = 'endpointoffboarding',

    [Parameter(Mandatory = $false)]
    [string]
    $AzureContainer = 'tpm-logs',

    [Parameter(Mandatory = $false)]
    [string]
    # Injected into WinPE by Build-OSDCloudWinPE.ps1 via startnet.cmd.
    # Never hard-code the value here - the script is meant to be public.
    $AzureSasToken = $env:TPM_SAS_TOKEN,
    # ----------------------------------------

    [Parameter(Mandatory = $false)]
    [string[]]
    $EmailRecipients = @(
        'Michael.hanson@state.sd.us',
        'Kelcey.Hanson@state.sd.us'
    ),

    [Parameter(Mandatory = $false)]
    [string]
    $SmtpServer = 'email.state.sd.us',

    [Parameter(Mandatory = $false)]
    [string]
    $EmailFrom = 'noreply@state.sd.us',

    [Parameter(Mandatory = $false)]
    [switch]
    $AlwaysSendEmail = $true
)

#region OSDCloud Initialization & Environmental Checks
$ScriptName = 'Clear-TPM-WinPE'
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$ScriptName.log"
$TranscriptPath = Join-Path "$env:SystemRoot\Temp" $Transcript
$null = Start-Transcript -Path $TranscriptPath -ErrorAction Ignore

# Phase Detection
if ($env:SystemDrive -eq 'X:') {
    $WindowsPhase = 'WinPE'
}
else {
    $ImageState = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State' -ErrorAction Ignore).ImageState
    if ($env:UserName -eq 'defaultuser0') {$WindowsPhase = 'OOBE'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE') {$WindowsPhase = 'Specialize'}
    elseif ($ImageState -eq 'IMAGE_STATE_SPECIALIZE_RESEAL_TO_AUDIT') {$WindowsPhase = 'AuditMode'}
    else {$WindowsPhase = 'Windows'}
}

# Admin Elevation Check
$whoiam = [system.security.principal.windowsidentity]::getcurrent().name
$isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isElevated) {
    Write-Error "[!] Running as $whoiam (NOT Admin Elevated). TPM operations require Administrator rights."
    Break
}

# SAS Token Fail-Fast
if ([string]::IsNullOrWhiteSpace($AzureSasToken)) {
    Write-Error "[!] AzureSasToken is empty. Expected via `$env:TPM_SAS_TOKEN (set by Build-OSDCloudWinPE.ps1). Aborting so we don't clear the TPM with no way to log the result."
    $null = Stop-Transcript -ErrorAction Ignore
    exit 2
}

# Transport Layer Security (TLS) 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#endregion

$LogFilePath = Join-Path "$env:SystemRoot\Temp" "TPM_CIM_Clear_Log.txt"
$TpmNamespace = "ROOT\CIMV2\Security\MicrosoftTpm"
$StartTime = Get-Date

Write-Host "DIAG: TPM_SAS_TOKEN present=$(-not [string]::IsNullOrWhiteSpace($env:TPM_SAS_TOKEN)) len=$($env:TPM_SAS_TOKEN.Length)"
Write-Host "DIAG: AzureSasToken param   present=$(-not [string]::IsNullOrWhiteSpace($AzureSasToken)) len=$($AzureSasToken.Length)"

# Pull the device serial number from BIOS (Win32_BIOS).
$DeviceSerialNumber = $null
try {
    $DeviceSerialNumber = (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
    if ($DeviceSerialNumber) {
        $DeviceSerialNumber = $DeviceSerialNumber.Trim()
    }
}
catch {
    $DeviceSerialNumber = $null
}
if ([string]::IsNullOrWhiteSpace($DeviceSerialNumber)) {
    $DeviceSerialNumber = $env:COMPUTERNAME
}

$LogData = @{
    Timestamp         = $StartTime
    ComputerName      = $EPMComputerName
    SerialNumber      = $DeviceSerialNumber
    HostName          = $env:COMPUTERNAME
    UserName          = $env:USERNAME
    UserDomain        = $env:USERDOMAIN
    OSVersion         = [System.Environment]::OSVersion.VersionString
    WindowsPhase      = $WindowsPhase
    ProcessId         = $PID
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    LogFile           = $LogFilePath
    Status            = $null
    ReturnValue       = $null
    ErrorMessage      = $null
    TPMInfo           = @{}
    ExecutionTime     = $null
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [switch]$IsError
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $(if($IsError){'ERROR: '})$Message"
    try {
        $LogMessage | Out-File -FilePath $LogFilePath -Append
    }
    catch {}

    if ($IsError) {
        Write-Error $Message
    }
    else {
        Write-Host $LogMessage
    }
}

function Send-TpmResultToAzure {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $Data
    )

    $payload = [PSCustomObject]@{
        ComputerName = $Data.ComputerName
        TestMode     = $TestMode
        Data         = $Data
    }

    $body = $payload | ConvertTo-Json -Depth 20
    
    # Format SAS Token
    $sas = $AzureSasToken
    if (-not $sas.StartsWith('?')) {
        $sas = "?$sas"
    }

    # Generate a unique filename for the blob drop
    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $serial = $Data.SerialNumber -replace '[^a-zA-Z0-9]', ''
    $blobName = "TPM_Result_${serial}_${timestamp}.json"
    
    $blobUri = "https://$AzureStorageAccount.blob.core.windows.net/$AzureContainer/$blobName$sas"
    
    # Required header for Azure Blob REST API PUT
    $headers = @{
        'x-ms-blob-type' = 'BlockBlob'
    }

    $response = Invoke-WebRequest -UseBasicParsing -Uri $blobUri -Method Put -Headers $headers -Body $body -ContentType 'application/json' -ErrorAction Stop

    $status = 0
    try { $status = [int]$response.StatusCode } catch { $status = 0 }
    
    # 201 Created is the expected success response for a new BlockBlob
    if ($status -lt 200 -or $status -ge 300) {
        throw "Azure Blob upload returned non-success HTTP $status. Body: $($response.Content)"
    }

    return $blobName
}

function Send-WinPEAlert {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Subject,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [Parameter()][string[]]$To = $EmailRecipients,
        [Parameter()][string]  $From = $EmailFrom,
        [Parameter()][string]  $Server = $SmtpServer,
        [Parameter()][int]     $Port = 25,
        [Parameter()][string]  $LocalLogPath = "$env:SystemRoot\Temp\Clear-TPM-Alert.log"
    )

    $taggedSubject = "[PSU-WINPE] $Subject".Trim()
    $isHtml = $Message -match '<'
    $hostName = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    $footer = if ($isHtml) {
        "<hr/><p style='color:#888;font-size:smaller;'>Sent by <strong>PowerShell Universal (PSU)</strong> - WinPE Clear-TPM alert from <strong>$hostName</strong> (S/N $DeviceSerialNumber) at $stamp</p>"
    }
    else {
        "`n`n----`nSent by PowerShell Universal (PSU) - WinPE Clear-TPM alert from $hostName (S/N $DeviceSerialNumber) at $stamp"
    }
    $finalBody = "$Message$footer"

    $smtp = $null
    try {
        $smtp = New-Object System.Net.Mail.SmtpClient($Server, $Port)
        $smtp.EnableSsl = $false 

        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($From)
        foreach ($addr in $To) {
            if (-not [string]::IsNullOrWhiteSpace($addr)) { $mail.To.Add($addr.Trim()) }
        }
        if ($mail.To.Count -eq 0) {
            throw "Send-WinPEAlert: no valid recipients supplied."
        }
        $mail.Subject = $taggedSubject
        $mail.Body = $finalBody
        $mail.IsBodyHtml = $isHtml

        $smtp.Send($mail)
        $mail.Dispose()
        Write-Log "Send-WinPEAlert: email sent to $($To -join ', ')"
        return $true
    }
    catch {
        Write-Log "Send-WinPEAlert: SMTP send failed: $($_.Exception.Message)" -IsError
        try {
            $logDir = Split-Path -Parent $LocalLogPath
            if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            $entry = @"
==== $stamp ====
Subject : $taggedSubject
To      : $($To -join ', ')
From    : $From
SMTP    : ${Server}:${Port}
SmtpErr : $($_.Exception.Message)
Body    :
$finalBody

"@
            Add-Content -LiteralPath $LocalLogPath -Value $entry -ErrorAction Stop
        }
        catch { }
        return $false
    }
    finally {
        if ($smtp) { $smtp.Dispose() }
    }
}

try {
    Write-Log "========================================"
    Write-Log "TPM Clear Operation Started"
    Write-Log "Phase: $WindowsPhase | Elevated: $isElevated"
    Write-Log "TestMode: $TestMode"
    Write-Log "Computer: $($LogData.ComputerName)"
    Write-Log "User: $($LogData.UserDomain)\$($LogData.UserName)"
    Write-Log "========================================"

    # 1. Get TPM Instance
    Write-Log "Retrieving TPM instance from namespace: $TpmNamespace"
    $tpm = Get-CimInstance -Namespace $TpmNamespace -ClassName Win32_Tpm -ErrorAction Stop

    if (-not $tpm) {
        Write-Log "No TPM instance found." -IsError
        $LogData.Status = "FAILED"
        $LogData.ErrorMessage = "No TPM instance found"
        $null = Send-TpmResultToAzure -Data $LogData
        $null = Stop-Transcript -ErrorAction Ignore
        exit 1
    }

    # Capture TPM Information
    $LogData.TPMInfo = @{
        IsActivated                 = $tpm.IsActivated_InitialValue
        IsEnabled                   = $tpm.IsEnabled_InitialValue
        IsOwned                     = $tpm.IsOwned_InitialValue
        ManufacturerId              = $tpm.ManufacturerId
        ManufacturerVersion         = $tpm.ManufacturerVersion
        SpecVersion                 = $tpm.SpecVersion
        PhysicalPresenceVersionInfo = $tpm.PhysicalPresenceVersionInfo
    }

    Write-Log "TPM Details:"
    Write-Log "  - IsActivated: $($LogData.TPMInfo.IsActivated)"
    Write-Log "  - IsEnabled: $($LogData.TPMInfo.IsEnabled)"
    Write-Log "  - IsOwned: $($LogData.TPMInfo.IsOwned)"
    Write-Log "  - Manufacturer: $($LogData.TPMInfo.ManufacturerId)"

    # 2. Attempt to Clear
    if ($TestMode) {
        Write-Log "TEST MODE ACTIVE: Skipping actual TPM Clear. Simulating success."
        $result = [PSCustomObject]@{ ReturnValue = 0 }
    }
    else {
        Write-Log "Invoking TPM Clear method..."
        $result = Invoke-CimMethod -InputObject $tpm -MethodName Clear -ErrorAction Stop
    }

    # 3. Evaluate Return Value
    Write-Log "Clear method returned: $($result.ReturnValue)"
    $LogData.ReturnValue = $result.ReturnValue

    if ($result.ReturnValue -eq 0) {
        Write-Log "SUCCESS: TPM clear command accepted. Reboot required."
        $LogData.Status = "SUCCESS"
        $exitCode = 0
    }
    elseif ($result.ReturnValue -eq 2150105089) {
        Write-Log "SUCCESS: TPM is already clear. No action needed."
        $LogData.Status = "SUCCESS_ALREADY_CLEAR"
        $exitCode = 0
    }
    else {
        Write-Log "TPM Clear failed with ReturnValue: 0x$($result.ReturnValue.ToString('X8'))" -IsError
        $LogData.Status = "FAILED"
        $LogData.ErrorMessage = "TPM Clear returned: 0x$($result.ReturnValue.ToString('X8'))"
        $exitCode = 1
    }
}
catch {
    Write-Log "Error: $_" -IsError
    $LogData.Status = "EXCEPTION"
    $LogData.ErrorMessage = $_.Exception.Message
    $exitCode = 1
}
finally {
    $LogData.ExecutionTime = ((Get-Date) - $StartTime).TotalSeconds
    Write-Log "Execution Time: $($LogData.ExecutionTime) seconds"
    Write-Log "========================================"

    # Send results to Azure
    $apiOk = $false
    $apiError = $null
    $uploadedBlobName = $null
    try {
        Write-Log "Uploading results to Azure Blob Storage: $AzureStorageAccount/$AzureContainer"
        $uploadedBlobName = Send-TpmResultToAzure -Data $LogData
        Write-Log "Results uploaded successfully as: $uploadedBlobName"
        $apiOk = $true
    }
    catch {
        $apiError = $_.Exception.Message
        Write-Log "Failed to upload results to Azure: $apiError" -IsError
    }

    if (-not $apiOk -or $AlwaysSendEmail) {
        $tpmDetails = $LogData.TPMInfo.GetEnumerator() | Sort-Object Key | ForEach-Object { 
            "  $($_.Key): $($_.Value)" 
        } | Out-String

        $emailSubject = if (-not $apiOk) {
            "Clear-TPM Azure Upload FAILED on $($LogData.ComputerName) (S/N $DeviceSerialNumber)"
        }
        else {
            "Clear-TPM completed on $($LogData.ComputerName) (S/N $DeviceSerialNumber) - status: $($LogData.Status)"
        }

        $headline = if (-not $apiOk) {
            "<p><strong>Clear-TPM was unable to upload its result JSON to Azure Storage.</strong></p><p>The TPM operation itself may have succeeded or failed - the file will be missing from the container either way. Reconcile manually.</p>"
        }
        else {
            "<p><strong>Clear-TPM run completed.</strong> Sent because -AlwaysSendEmail was specified. The Azure Blob upload succeeded ($uploadedBlobName).</p>"
        }

        $emailBody = @"
$headline
<table border='1' cellpadding='4' cellspacing='0' style='border-collapse:collapse;'>
<tr><td><strong>Computer (EPM)</strong></td><td>$($LogData.ComputerName)</td></tr>
<tr><td><strong>Serial</strong></td><td>$DeviceSerialNumber</td></tr>
<tr><td><strong>Host (WinPE)</strong></td><td>$($LogData.HostName)</td></tr>
<tr><td><strong>Windows Phase</strong></td><td>$WindowsPhase</td></tr>
<tr><td><strong>User</strong></td><td>$($LogData.UserDomain)\$($LogData.UserName)</td></tr>
<tr><td><strong>TestMode</strong></td><td>$TestMode</td></tr>
<tr><td><strong>Azure Target</strong></td><td>$AzureStorageAccount/$AzureContainer</td></tr>
<tr><td><strong>Upload result</strong></td><td>$(if ($apiOk) { "OK ($uploadedBlobName)" } else { [System.Net.WebUtility]::HtmlEncode([string]$apiError) })</td></tr>
<tr><td><strong>TPM clear status</strong></td><td>$($LogData.Status)</td></tr>
<tr><td><strong>TPM ReturnValue</strong></td><td>$($LogData.ReturnValue)</td></tr>
<tr><td><strong>TPM error msg</strong></td><td>$([System.Net.WebUtility]::HtmlEncode([string]$LogData.ErrorMessage))</td></tr>
<tr><td><strong>Execution time</strong></td><td>$($LogData.ExecutionTime) s</td></tr>
</table>
<p><strong>TPM details</strong></p>
<pre>$([System.Net.WebUtility]::HtmlEncode($tpmDetails))</pre>
"@

        Send-WinPEAlert -Subject $emailSubject -Message $emailBody | Out-Null
    }
    
    $null = Stop-Transcript -ErrorAction Ignore
}

#region Post-Run Action ------------------------------------------------
# On success: shut the machine down (unless TestMode).
# On failure: open the logs in Notepad so the tech can review before the
# WinPE session ends.
if ($exitCode -eq 0) {
    if ($TestMode) {
        Write-Host "TestMode is ON - skipping shutdown. Exit code: $exitCode" -ForegroundColor Yellow
    }
    else {
        Write-Host "TPM clear succeeded. Shutting down in 10 seconds..." -ForegroundColor Green
        Start-Sleep -Seconds 10
        if ($WindowsPhase -eq 'WinPE') {
            & wpeutil.exe shutdown
        }
        else {
            & shutdown.exe /s /f /t 0
        }
    }
}
else {
    Write-Host "TPM clear FAILED (exit $exitCode). Opening logs for review..." -ForegroundColor Red
    try {
        if (Test-Path -LiteralPath $LogFilePath) {
            Start-Process -FilePath notepad.exe -ArgumentList "`"$LogFilePath`""
        }
        if (Test-Path -LiteralPath $TranscriptPath) {
            # -Wait on the transcript so the WinPE session stays alive
            # until the tech closes the window.
            Start-Process -FilePath notepad.exe -ArgumentList "`"$TranscriptPath`"" -Wait
        }
    }
    catch {
        Write-Warning "Could not launch Notepad for log review: $($_.Exception.Message)"
    }
}
#endregion Post-Run Action ---------------------------------------------

exit $exitCode
