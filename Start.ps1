# Set the execution policy for the current process to avoid security errors.
# This is generally safe for scripts you trust.
try {
    Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
}
catch {
    Write-Warning "Could not set execution policy. This might cause issues on some systems."
    Write-Warning "Error: $($_.Exception.Message)"
}

# Cybersecurity Training Start Script
# Created by Mike Law
# Creation Date: 2025-08-23
# Last updated: 2025-10-18 
# version 2025.10.18
# Purpose: Allow users to update the scripts, programs, and trigger the setup as well as run the scoring script.

Add-Type -AssemblyName System.Windows.Forms
# TODO: Add option to preconfigured csv files for setup script. This will allow for quick setup of different predefined scenarios.
# TODO: Company categories for required software installs and readme scenario 

#region MARK: Virtual Machine Check
function Test-IsVirtualMachine {
    try {
        $model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
        $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
        if ($model -match 'Virtual' -or $manufacturer -match 'VMware|Microsoft|Xen|innotek|QEMU|Oracle') {
            return $true
        }
    } catch {
        # If CIM/WMI fails, assume it might not be a VM and proceed with caution.
        Write-Warning "Could not determine if this is a virtual machine. Proceeding with caution."
    }
    return $false
}

if (-not (Test-IsVirtualMachine)) {
    # Create a custom form to allow for custom button text
    $warningForm = New-Object System.Windows.Forms.Form
    $warningForm.Text = "Physical Machine Detected"
    $warningForm.Size = New-Object System.Drawing.Size(450, 180)
    $warningForm.StartPosition = "CenterScreen"
    $warningForm.FormBorderStyle = "FixedDialog"
    $warningForm.MaximizeBox = $false
    $warningForm.MinimizeBox = $false

    $messageLabel = New-Object System.Windows.Forms.Label
    $messageLabel.Text = "This script is designed to be run on a virtual machine and could result in unwanted software and users added to your system if you choose to continue."
    $messageLabel.Location = New-Object System.Drawing.Point(20, 20)
    $messageLabel.Size = New-Object System.Drawing.Size(400, 80)
    $warningForm.Controls.Add($messageLabel)

    $btnContinue = New-Object System.Windows.Forms.Button
    $btnContinue.Text = "CONTINUE ANYWAY"
    $btnContinue.Location = New-Object System.Drawing.Point(130, 110)
    $btnContinue.Size = New-Object System.Drawing.Size(140, 30)
    $btnContinue.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $warningForm.Controls.Add($btnContinue)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(280, 110)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $warningForm.Controls.Add($btnCancel)

    $dialogResult = $warningForm.ShowDialog()
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::Cancel) {
        Exit
    }
}
#endregion


# Set working paths and logging
$scriptpath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptpath
$logpath = "$scriptpath\logs"
if (!(Test-Path $logpath)) { New-Item -ItemType Directory -Path $logpath | Out-Null }
$logfile = "$logpath\cybersec_score_log_$(Get-Date -Format 'yyyyMMdd').txt"
if (!(Test-Path $logfile)) { New-Item -ItemType File -Path $logfile | Out-Null }

# Clear the log file on startup if the option is enabled
if ($clearlog -eq "yes" -and (Test-Path $logfile)) {
    Clear-Content -Path $logfile
    Write-Host "Log file for today has been cleared as per configuration."
}

# Logging function
function Log-Message {
    param ([string]$message, [string]$type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # --- DEBUGGING: Check if the logfile path is valid ---
    if ([string]::IsNullOrEmpty($script:logfile)) {
        Write-Error "Log-Message FATAL: `$script:logfile variable is null or empty. Cannot write log. Message was: [$type] $message"
        return # Stop execution of this function to prevent the Add-Content error
    }
    Add-Content -Path $script:logfile -Value "$timestamp [$type] $message"
}


#region MARK: Configuration variables
$updateenabled = "Internet"
$updatecachelocation = "$env:TEMP\cybersec"
$updateLANtest = "\\192.168.2.130\cybersec" # Example LAN path for updates
# The base URL for your GitHub repository's releases.
# Replace 'YOUR_GITHUB_USERNAME', 'YOUR_REPO_NAME', and 'YOUR_TAG' accordingly.
$updateloc = "https://github.com/miklaw/Cybersec-practice/releases/download/v/" # Example for release tag 'v1.0'
$updatescripts = "Setup.zip"
$updatemalware = "malware.zip"
$updateprograms = "programs.zip"
$updateconfig = "config.zip"
$updatesaltedfiles = "saltedfiles.zip"
$webauth = "No"
$clearlog = "yes" # Set to "yes" to clear the log file on startup
# Default script parameters. These can be overridden by the config file.
$scriptparamfile = "$scriptpath\config\scriptparams.cfg"
$scriptparams = @{
    randomusernumber           = "6"
    randomgroupnumber          = "3"
    randomfakeusernumber       = "1"
    randomfakegroupnumber      = "1"
    randomprogramnumbers       = "2"
    randommalwarenumbers       = "2"
    randommanualmalwarenumbers = "2"
    randomunauthorizednumbers  = "1"
    numberofbuiltingroups      = "1"
    passwordchangedate         = "2025-01-01"
    randomscheduledtasks       = "2"
}
$debugscripts = $false #if This is set to true, the script windows will remain open to give us time to view their output
#endregion  

# --- MARK: Load and Validate Configuration ---
# Define the default parameters first.
$defaultParams = $scriptparams.Clone()

if (Test-Path $scriptparamfile) {
    try {
        $loadedParams = Get-Content -Path $scriptparamfile -Raw | ConvertFrom-StringData
        # Merge defaults with loaded params. This adds any new keys from defaults.
        foreach ($key in $defaultParams.Keys) {
            if (-not $loadedParams.ContainsKey($key)) {
                $loadedParams[$key] = $defaultParams[$key]
                Log-Message "Added missing config key '$key' with default value." "INFO"
            }
        }
        $scriptparams = $loadedParams
        Log-Message "Successfully loaded and validated script parameters from '$scriptparamfile'." "INFO"
    } catch {
        Log-Message "Config file '$scriptparamfile' was invalid. Using default values. Error: $($_.Exception.Message)" "WARN"
        $scriptparams = $defaultParams
    }
} else {
    Log-Message "No config file found. Using default script parameters." "INFO"
    $scriptparams = $defaultParams
}
# Save the (potentially updated) configuration back to the file.
$scriptparams.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" } | Set-Content -Path $scriptparamfile

$script:configTextBoxes = @{} # Initialize the hashtable to store references to textboxes

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
    "Update Scripts"     = $updatescripts
    "Update Malware"     = $updatemalware
    "Update Programs"    = $updateprograms
    "Update Config"      = $updateconfig
    "Update Removal Files" = $updatesaltedfiles
}

$checkboxes = @{}
$y = 20
foreach ($label in $updateOptions.Keys) {
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $label
    $chk.Location = New-Object System.Drawing.Point(30, $y)
    $chk.Size = New-Object System.Drawing.Size(500, 30)
    $tabUpdates.Controls.Add($chk)
    $checkboxes[$label] = $chk
    $y += 35
}

$btnUpdateSelected = New-Object System.Windows.Forms.Button
$btnUpdateSelected.Text = "Download Selected Updates"
$btnUpdateSelected.Dock = "Bottom"
$btnUpdateSelected.Height = 40
$btnUpdateSelected.Margin = New-Object System.Windows.Forms.Padding(10)
$btnUpdateSelected.Add_Click({
    Log-Message "Update process started by user." "INFO"
    $form.Refresh()

    $filesToUpdate = @()
    foreach ($label in $checkboxes.Keys) {
        $checkbox = $checkboxes[$label]
        if ($checkbox.Checked) {
            $filesToUpdate += @{
                Label = $label
                Filename = $updateOptions[$label]
                LocalPath = ""
                ExtractPath = ""
            }
        }
    }

    if ($filesToUpdate.Count -eq 0) {
        Log-Message "Update process cancelled: No updates were selected." "WARN"
        return
    }
    If (!(Test-Path $updatecachelocation)) {
        New-Item -ItemType Directory -Path $updatecachelocation | Out-Null
        Log-Message "Created update cache directory at $updatecachelocation" "INFO"
    }

    # --- Phase 1: Download all files ---
    $statusLabel.Text = "Phase 1: Downloading all selected files..."
    Log-Message "--- Starting Download Phase ---" "INFO"
    foreach ($file in $filesToUpdate) {
        Log-Message "Attempting to download $($file.Label)..." "INFO"
        try {
            $localUpdateFile = Join-Path $updatecachelocation $file.Filename
            $updateurl = if ($updateenabled -eq "Internet") { "$updateloc/$($file.Filename)" }
                         elseif ($updateenabled -eq "LAN" -and (Test-Path $updateLANtest)) { "$updateLANtest\$($file.Filename)" }
                         else { throw "Invalid update method or LAN path inaccessible." }

            $webClient = New-Object System.Net.WebClient
            if ($webauth -eq "Yes") { $webClient.Credentials = Get-Credential -Message "Enter credentials for update" }
            $webClient.DownloadFile($updateurl, $localUpdateFile)

            $file.LocalPath = $localUpdateFile
            Log-Message "Successfully downloaded $($file.Filename) to $localUpdateFile" "INFO"
        } catch {
            Log-Message "Download failed for $($file.Label): $($_.Exception.Message)" "ERROR"
        }
    }

    # --- Phase 2: Extract all files ---
    Log-Message "--- Starting Extraction Phase ---" "INFO"
    foreach ($file in $filesToUpdate) {
        if (-not $file.LocalPath) { continue } # Skip if download failed
        Log-Message "Attempting to extract $($file.Label)..." "INFO"
        $form.Refresh()
        try {
            # Use 7-Zip for extraction to robustly handle long file paths.
            # First, check for a standard installation.
            $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
            if (-not (Test-Path $sevenZipPath)) {
                Log-Message "Standard 7-Zip installation not found. Checking temp cache..." "INFO"
                # If not found, fall back to the temp directory version.
                $sevenZipPath = Join-Path $updatecachelocation "7z.exe"
                if (-not (Test-Path $sevenZipPath)) {
                    Log-Message "7-Zip not found in temp cache. Downloading..." "INFO"
                    $form.Refresh()
                    $sevenZipUrl = "https://www.7-zip.org/a/7z.exe"
                    (New-Object System.Net.WebClient).DownloadFile($sevenZipUrl, $sevenZipPath)
                    Log-Message "7-Zip downloaded successfully." "INFO"
                }
            }
            $form.Refresh()
            $arguments = "x `"$($file.LocalPath)`" -o`"$scriptpath`" -y"
            Start-Process -FilePath $sevenZipPath -ArgumentList $arguments -Wait -NoNewWindow

            Log-Message "Successfully extracted $($file.Filename) to $scriptpath" "INFO"
        } catch {
            Log-Message "Extraction failed for $($file.Label): $($_.Exception.Message)" "ERROR"
        }
    }
    Log-Message "Update process finished." "INFO"
})
$tabUpdates.Controls.Add($btnUpdateSelected)
$tabUpdates.Padding = New-Object System.Windows.Forms.Padding(10)

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

### MARK: TAB 4: Config ###
$tabConfig = New-Object System.Windows.Forms.TabPage
$tabConfig.Text = "Config"

# Use a TableLayoutPanel to structure the tab with a button at the top
$configTableLayout = New-Object System.Windows.Forms.TableLayoutPanel
$configTableLayout.Dock = "Fill"
$configTableLayout.ColumnCount = 1
$configTableLayout.RowCount = 2
$configTableLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$configTableLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$tabConfig.Controls.Add($configTableLayout)

$btnSaveConfig = New-Object System.Windows.Forms.Button
$btnSaveConfig.Text = "Save Config"
$btnSaveConfig.Size = New-Object System.Drawing.Size(100, 30)
$btnSaveConfig.Anchor = "None" # Center the button
$btnSaveConfig.Margin = New-Object System.Windows.Forms.Padding(5)

$btnSaveConfig.Add_Click({
    Log-Message "Attempting to save configuration." "INFO"
    try {
        # Create the output content directly from the textboxes
        $output = foreach ($key in ($script:configTextBoxes.Keys | Sort-Object)) {
            if ($script:configTextBoxes.ContainsKey($key)) {
                $value = $script:configTextBoxes[$key].Text
                "$key=$value" # No longer wrapping values in quotes
            }
        }

        # Write to the config file, overwriting existing content
        Set-Content -Path $scriptparamfile -Value $output -Force
        Log-Message "Configuration saved successfully to $scriptparamfile." "INFO"
        [System.Windows.Forms.MessageBox]::Show("Configuration saved successfully!", "Save Config", "OK", "Information")
    } catch {
        Log-Message "Failed to save configuration: $($_.Exception.Message)" "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Failed to save configuration: $($_.Exception.Message)", "Error", "OK", "Error")
    }
})
# Create a panel to hold the button and center it
$topPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$topPanel.Dock = "Fill"
$topPanel.FlowDirection = "TopDown"
$topPanel.Controls.Add($btnSaveConfig)
$configTableLayout.Controls.Add($topPanel, 0, 0)

$configPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$configPanel.Dock = "Fill"
$configPanel.FlowDirection = "TopDown"
$configPanel.AutoScroll = $true
$configPanel.WrapContents = $false

$configTableLayout.Controls.Add($configPanel, 0, 1)

### MARK: TAB 5: Scripts ###
$tabScripts = New-Object System.Windows.Forms.TabPage
$tabScripts.Text = "Scripts"

# Find all .ps1 files in the script's root directory, excluding this script itself.
$availableScripts = Get-ChildItem -Path $scriptpath -Filter *.ps1 | Where-Object {
    ($_.Name -ne $MyInvocation.MyCommand.Name) -and ($_.Name -ne 'Start.ps1') -and ($_.Name -ne 'Cybersec requirements setup.ps1')
}

$yPos = 20
foreach ($scriptFile in $availableScripts) {
    $btnScript = New-Object System.Windows.Forms.Button
    $btnScript.Text = "Run $($scriptFile.Name)"
    $btnScript.Location = New-Object System.Drawing.Point(30, $yPos)
    $btnScript.Size = New-Object System.Drawing.Size(500, 30)
    # Store the full path in the Tag property to use it in the click event.
    $btnScript.Tag = $scriptFile.FullName

    $btnScript.Add_Click({
        $scriptToRun = $this.Tag
        Log-Message "User clicked to run script: $scriptToRun" "INFO"
        
        # Determine which function to call based on the script name
        $scriptName = (Get-Item $scriptToRun).Name
        $functionName = switch -Wildcard ($scriptName) {
            "*setup.ps1"       { "Invoke-CybersecSetup" }
            "*score card.ps1"  { "Invoke-OpenScoreCard" }
            default            { "" }
        }

        try {
            if ([string]::IsNullOrEmpty($functionName)) {
                Log-Message "No associated function found for script '$scriptName'. Cannot run." "WARN"
                return
            }

            # For GUI-based scripts like setup and scorecard, run them in a new, separate process
            # to ensure stability and prevent the main dashboard from freezing.
            if ($functionName -in "Invoke-OpenScoreCard", "Invoke-CybersecSetup") {
                $argumentList = "-NoProfile -ExecutionPolicy Bypass"
                if ($debugscripts) {
                    $argumentList += " -NoExit"
                }
                $argumentList += " -File `"$scriptToRun`""

                # The setup script is designed to accept a log file path, but the scorecard script is not.
                if ($scriptName -like "*setup.ps1") {
                    $argumentList += " -SetupLogFile `"$logfile`""
                }
                Log-Message "Starting '$scriptName' in a new process with arguments: $argumentList" "INFO"
                Start-Process powershell.exe -ArgumentList $argumentList
                return
            }

            # Fallback for any other scripts you might add later.
            Log-Message "Running '$scriptName' in the current process." "INFO"
            & $scriptToRun
        } catch {
            Log-Message "Failed to start job for script '$scriptName'. Error: $_" "ERROR"
        }
    })
    $tabScripts.Controls.Add($btnScript)
    $yPos += 40
}

$tabs.Controls.Add($tabScripts)
$tabs.Controls.Add($tabConfig)
$tabs.Controls.Add($tabUpdates)
$tabs.Controls.Add($tabLogs)
$form.Controls.Add($tabs)

# Dynamically resize the form based on the number of config items
$form.Add_Load({
    # This block runs right before the form is displayed.
    # We will populate the config tab here to ensure it uses the correct, loaded $scriptparams.
    
    # Clear any existing controls in case this event ever runs more than once.
    $configPanel.Controls.Clear()

    # Dynamically create labels and textboxes for each script parameter
    foreach ($key in ($scriptparams.Keys | Sort-Object)) {
        $value = $scriptparams[$key]

        $panel = New-Object System.Windows.Forms.Panel
        $panel.Size = New-Object System.Drawing.Size(550, 30)
        $panel.Margin = New-Object System.Windows.Forms.Padding(5)

        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = "$($key.ToString()):"
        $lbl.Location = New-Object System.Drawing.Point(10, 5)
        $lbl.AutoSize = $true
        $panel.Controls.Add($lbl)

        $txt = New-Object System.Windows.Forms.TextBox
        $txt.Text = $value
        $txt.Location = New-Object System.Drawing.Point(200, 2)
        $txt.Size = New-Object System.Drawing.Size(320, 20)
        $panel.Controls.Add($txt)
        
        $script:configTextBoxes[$key] = $txt # Store textbox reference
        $configPanel.Controls.Add($panel)
    }

    # Calculate required height for the config tab
    $configItemHeight = 40 # Approximate height for each config item (panel margin + control height)
    $buttonAreaHeight = 60 # Height for the save button area
    $tabHeaderHeight = 25
    $formPadding = 60 # Padding for the form itself (title bar, borders)

    $requiredHeight = ($scriptparams.Count * $configItemHeight) + $buttonAreaHeight + $tabHeaderHeight + $formPadding
    
    # Ensure the form is not smaller than its original size or larger than the screen
    $minHeight = 450
    $maxHeight = (Get-WmiObject -Class Win32_VideoController).CurrentVerticalResolution
    
    $newHeight = [System.Math]::Max($minHeight, $requiredHeight)
    $form.Height = [System.Math]::Min($newHeight, $maxHeight)
})

[void]$form.ShowDialog()
Log-Message "Application closed." "INFO"
# End of script