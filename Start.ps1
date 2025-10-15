# Set the execution policy for the current process to avoid security errors.
# This is generally safe for scripts you trust.
try {
    Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
}
catch {
    Write-Warning "Could not set execution policy. This might cause issues on some systems."
    Write-Warning "Error: $($_.Exception.Message)"
}

# Cybersecurity Training Script
# Created by Mike Law
# Creation Date: 2025-08-23
# Last updated: 2025-08-23 
# version 1.0
# Purpose: Allow users to update the scripts, programs, and trigger the setup as well as run the scoring script.

Add-Type -AssemblyName System.Windows.Forms

# Set working paths and logging
$scriptpath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptpath
$logpath = "$scriptpath\logs"
if (!(Test-Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
$logfile = "$logpath\cybersec_score_log_$(Get-Date -Format 'yyyyMMdd').txt"
if (!(Test-Path $logfile)) { New-Item -ItemType File -Path $logfile | Out-Null }

# Logging function
function Log-Message {
    param ([string]$message, [string]$type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logfile -Value "$timestamp [$type] $message"
}

#region MARK: Configuration variables
$version = 20251013
$versionline = 36 # Line number in this script where $version is defined
$updateenabled = "Internet"
$updatecachelocation = "$env:TEMP\cybersec"
$updateLANtest = "\\192.168.2.130\cnc"
$updateloc = "https://drive.google.com/drive/folders/1QInXxSHWH9ZEW5lzx68FxLn0lQgiShVw?usp=sharing" # The network location that holds csv files that you may want to update.  This can be in the form of a file share like \\server\share or use a 
$updatescripts = "Setup.zip"
$updatemalware = "malware.zip"
$updateprograms = "programs.zip"
$updateotherfiles = "otherfiles.zip"
$webauth = "No"
$updatefromzip = "Yes"
$updatecheckfile = "Start.ps1"
#endregion  

#region MARK: Update function (same as your original)
function Check-ForUpdates {
    param (
        [string]$updateenabled, [string]$updateloc, [string]$updatefile,
        [string]$webauth, [string]$updatecachelocation, [string]$updatefromzip,
        [string]$updatecheckfile, [int]$version, [int]$versionline, [string]$updateLANtest
    )

    if ($updateenabled -eq "None") {
        Log-Message "Update function is disabled." "INFO"
        return
    }

    $updateurl = if ($updateenabled -eq "Internet") { "$updateloc$updatefile" }
                 elseif ($updateenabled -eq "LAN" -and (Test-Path $updateLANtest)) { "$updateLANtest\$updatefile" }
                 else { Log-Message "Invalid update method or LAN path inaccessible." "ERROR"; return }

    if (!(Test-Path $updatecachelocation)) { New-Item -ItemType Directory -Path $updatecachelocation | Out-Null }
    $localUpdateFile = "$updatecachelocation\$updatefile"

    try {
        if ($webauth -eq "Yes") {
            $credentials = Get-Credential -Message "Enter credentials for update"
            Invoke-WebRequest -Uri $updateurl -OutFile $localUpdateFile -Credential $credentials -ErrorAction Stop
        } else {
            Invoke-WebRequest -Uri $updateurl -OutFile $localUpdateFile -ErrorAction Stop
        }
        Log-Message "Downloaded update file: $localUpdateFile" "INFO"
    } catch {
        Log-Message "Download failed: $($_.Exception.Message)" "ERROR"
        return
    }
 # MARK: Extract from zip and apply update
    if ($updatefromzip -eq "Yes") {
        $tempExtractPath = "$updatecachelocation\extracted"
        if (Test-Path $tempExtractPath) { Remove-Item $tempExtractPath -Recurse -Force }
        New-Item -ItemType Directory -Path $tempExtractPath | Out-Null

        try {
            Expand-Archive -Path $localUpdateFile -DestinationPath $tempExtractPath -Force
            Log-Message "Extracted update to $tempExtractPath" "INFO"
        } catch {
            Log-Message "Extraction failed: $($_.Exception.Message)" "ERROR"
            return
        }

        $extractedScriptPath = "$tempExtractPath\$updatecheckfile"
        if (Test-Path $extractedScriptPath) {
            $extractedVersionLine = Get-Content $extractedScriptPath | Select-Object -Index ($versionline - 1)
            if ($extractedVersionLine -match '\$version\s*=\s*(\d+)') {
                $extractedVersion = [int]$matches[1]
                if ($extractedVersion -gt $version) {



                    Copy-Item "$tempExtractPath\*" $scriptpath -Recurse -Force
                    Log-Message "Updated to version $extractedVersion" "INFO"
                } else {
                    Log-Message "Already using latest version ($version)" "INFO"
                }
            } else {
                Log-Message "Version line not found in extracted script." "ERROR"
            }
        } else {
            Log-Message "Update check file not found in extracted contents." "ERROR"
        }

        Remove-Item $tempExtractPath -Recurse -Force
    } else {
        Log-Message "Update from zip is disabled." "ERROR"
    }

    Remove-Item $localUpdateFile -Force
    Log-Message "Update process completed." "INFO"
}
#endregion

#region GUI setup
# MARK: Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Cybersecurity Training Dashboard"
$form.Size = New-Object System.Drawing.Size(600,450)
$form.StartPosition = "CenterScreen"

# Create TabControl
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Size = New-Object System.Drawing.Size(580,400)
$tabs.Location = New-Object System.Drawing.Point(10,10)

### MARK: TAB 1: Updates ###
$tabUpdates = New-Object System.Windows.Forms.TabPage
$tabUpdates.Text = "Updates"

$updateOptions = @{
    "Update Scripts" = $updatescripts
    "Update Malware" = $updatemalware
    "Update Programs" = $updateprograms
    "Update Other Files" = $updateotherfiles
}

$y = 20
foreach ($label in $updateOptions.Keys) {
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $label
    $btn.Location = New-Object System.Drawing.Point(30,$y)
    $btn.Size = New-Object System.Drawing.Size(500,30)
    $btn.Add_Click({
        $selectedFile = $updateOptions[$label]
        $timestamp = Get-Date -Format "HH:mm:ss"
        $statusLabel.Text = "$timestamp - Updating: $label"
        Log-Message "User selected to update: $label" "INFO"
        $progressBar.Visible = $true
        $form.Refresh()

        try {
            Check-ForUpdates -updateenabled $updateenabled -updateloc $updateloc -updatefile $selectedFile -webauth $webauth -updatecachelocation $updatecachelocation -updatefromzip $updatefromzip -updatecheckfile $updatecheckfile -version $version -versionline $versionline -updateLANtest $updateLANtest
            $timestamp = Get-Date -Format "HH:mm:ss"
            $statusLabel.Text = "$timestamp - ✅ $label updated successfully."
            $historyBox.Items.Add("$timestamp - ✅ $label updated successfully.")
            Log-Message "Update for '$label' completed successfully." "INFO"
        } catch {
            $errorMsg = $_.Exception.Message
            $timestamp = Get-Date -Format "HH:mm:ss"
            $statusLabel.Text = "$timestamp - ❌ $label update failed."
            $historyBox.Items.Add("$timestamp - ❌ $label update failed.")
            Log-Message "Update for '$label' failed: $errorMsg" "ERROR"
        }

        $progressBar.Visible = $false
    })
    $tabUpdates.Controls.Add($btn)
    $y += 40
}

### MARK: TAB 2: Status ###
$tabStatus = New-Object System.Windows.Forms.TabPage
$tabStatus.Text = "Status"

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(30,20)
$progressBar.Size = New-Object System.Drawing.Size(500,20)
$progressBar.Style = 'Marquee'
$progressBar.Visible = $false
$tabStatus.Controls.Add($progressBar)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(30,50)
$statusLabel.Size = New-Object System.Drawing.Size(500,20)
$statusLabel.Text = ""
$tabStatus.Controls.Add($statusLabel)

$historyBox = New-Object System.Windows.Forms.ListBox
$historyBox.Location = New-Object System.Drawing.Point(30,80)
$historyBox.Size = New-Object System.Drawing.Size(500,250)
$tabStatus.Controls.Add($historyBox)

### MARK: TAB 3: Logs ###
$tabLogs = New-Object System.Windows.Forms.TabPage
$tabLogs.Text = "Logs"

$btnViewLog = New-Object System.Windows.Forms.Button
$btnViewLog.Text = "Open Log File"
$btnViewLog.Location = New-Object System.Drawing.Point(30,30)
$btnViewLog.Size = New-Object System.Drawing.Size(200,30)

$btnViewLog.Add_Click({
    if (Test-Path $logfile) {
        Start-Process notepad.exe $logfile
        Log-Message "User opened log file." "INFO"
    } else {
        [System.Windows.Forms.MessageBox]::Show("Log file not found.","Error","OK","Error")
        Log-Message "Log file not found when user tried to open it." "ERROR"
    }
})
$tabLogs.Controls.Add($btnViewLog)
$tabs.Controls.Add($tabUpdates)
$tabs.Controls.Add($tabStatus)
$tabs.Controls.Add($tabLogs)
$form.Controls.Add($tabs)
[void]$form.ShowDialog()
Log-Message "Application closed." "INFO"
# End of script