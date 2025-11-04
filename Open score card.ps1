function Invoke-OpenScoreCard {
    param([string]$PSScriptRoot)
    Log-Message "--- Starting Score Card Generation ---" "INFO"

# Load the necessary .NET assemblies for creating a graphical user interface.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region MARK: "In Progress" Splash Screen
# Create a simple form to show that scoring is in progress.
# This is crucial to keep the GUI thread alive in the runspace.
$progressForm = New-Object System.Windows.Forms.Form
$progressForm.Text = "Scoring..."
$progressForm.Size = New-Object System.Drawing.Size(400, 150)
$progressForm.StartPosition = "CenterScreen"
$progressForm.FormBorderStyle = "FixedDialog"
$progressForm.ControlBox = $false # Hide close button

$progressLabel = New-Object System.Windows.Forms.Label
$progressLabel.Text = "Scoring in progress... Please wait."
$progressLabel.Font = New-Object System.Drawing.Font("Arial", 12)
$progressLabel.Dock = "Fill"
$progressLabel.TextAlign = "MiddleCenter"
$progressForm.Controls.Add($progressLabel)

# Show the form without blocking the script.
$progressForm.Show()
$progressForm.Refresh()
[System.Windows.Forms.Application]::DoEvents()
#endregion

##############################################################################################
#region MARK: Variables
##############################################################################################
# Define the number of users, groups, and programs to select

# Define file paths
$tempDir = Join-Path $PSScriptRoot 'temp'
$Logfile = Join-Path $PSScriptRoot 'logs\score.log'

$tempusersFile = Join-Path $tempDir 'tempusers.csv'
$tempgroupsFile = Join-Path $tempDir 'tempgroups.csv'
$installedProgramsFile = Join-Path $tempDir 'installed.csv'

$scoreFile = Join-Path $tempDir 'scores.csv'


##############################################################################################
#endregion

# MARK: Score File prep
Log-Message "Preparing score files..." "INFO"
if (Test-Path $tempusersFile) {
    Log-Message "Found $tempusersFile" "DEBUG"
}
else {
    Log-Message "File $tempusersFile not found. Please run the Cybersec Practice setup.ps1 script first." "ERROR"
    exit
}
if (Test-path $tempgroupsFile) {
    Log-Message "Found $tempgroupsFile" "DEBUG"
}
else {
    Log-Message "File $tempgroupsFile not found. Please run the setup script first." "ERROR"
    exit
}
If (Test-path $scoreFile) {
    Log-Message "Removing $scoreFile" "INFO"
    Remove-item $scoreFile
}
else {
    Log-Message "File $scoreFile not found." "INFO"
}


##############################################################################################
#region MARK: Software Scoring Logic
##############################################################################################
Log-Message "Starting software scoring process..." "INFO"

# Import the list of programs to be checked.
try {
    $installedPrograms = Import-Csv $installedProgramsFile -ErrorAction Stop
    Log-Message "Successfully imported $($installedPrograms.Count) programs from '$installedProgramsFile'." "INFO"
    
    # ADDED: Check if the imported CSV file is actually empty.
    if ($null -eq $installedPrograms -or $installedPrograms.Count -eq 0) {
        Log-Message "The file '$installedProgramsFile' was loaded, but it appears to be empty or only contain a header. Please ensure it contains program data to be scored. Halting script." "ERROR"
        exit 1
    }
}
catch {
    Log-Message "Failed to import CSV file '$installedProgramsFile'. Error details: $($_.Exception.Message)" "ERROR"
    exit 1
}


# Initialize an empty array to hold the results of our checks.
$scoreResults = @()

# Get current local security policy settings by parsing 'net accounts'
$liveSecPol = @{}
try {
    $netAccountsOutput = net accounts
    $netAccountsOutput | ForEach-Object {
        if ($_ -match ':\s*(.+)$') {
            $key = ($_.Split(':')[0]).Trim()
            $value = $Matches[1].Trim()
            if ($value -ne "Never") { $value = ($value -split " ")[0] } # Extract numbers
            $liveSecPol[$key] = $value
        }
    }
    Log-Message "Successfully parsed live security policy settings from 'net accounts'." "INFO"    
    # On newer Windows versions, 'net accounts' does not show complexity. Use secedit as a fallback.
    $tempSecPolFile = Join-Path $tempDir "secpol.cfg"
    secedit /export /cfg $tempSecPolFile /quiet
    if (Test-Path $tempSecPolFile) {
        $secpolContent = Get-Content $tempSecPolFile
        $complexityLine = $secpolContent | Select-String -Pattern "PasswordComplexity"
        if ($complexityLine -match "=\s*1") {
            $liveSecPol['Password must meet complexity requirements'] = 'Enabled'
            Log-Message "Secedit check: Password complexity is Enabled." "DEBUG"
        } else {
            $liveSecPol['Password must meet complexity requirements'] = 'Disabled'
            Log-Message "Secedit check: Password complexity is Disabled." "DEBUG"
        }
        Remove-Item $tempSecPolFile -Force
    }
} catch {
    Log-Message "Failed to parse security policy settings. Scoring may be incomplete. Error: $($_.Exception.Message)" "ERROR"
}
# Loop through each program from the imported CSV file.
foreach ($program in $installedPrograms) {
    
    # ADDED: A try/catch block to handle errors for a single program without crashing the script.
    try {
        Log-Message "Processing Program: $($program.FriendlyName) (Type: $($program.Type))" "DEBUG"

        # Initialize result variables for the current program.
        $result = 0
        $hardmoderesult = $null
        $hardmoderesult2 = $null

        # --- MARK: Software Detection Logic ---
        if ($program.Type -in @('safe', 'malware', 'manualmalware', 'Unauthorized', 'Tempfiles')) {
            
            # ADDED: Check for null or empty path before testing.
            if (-not ([string]::IsNullOrEmpty($program.Detection))) {
                Log-Message "[STANDARD CHECK] Detection Method: $($program.DetectionMethod), Path: $($program.Detection)" "DEBUG"
                
                # Check if the detection path actually exists.
                $pathExists = Test-Path -LiteralPath $program.Detection
                Log-Message "[STANDARD CHECK] Does path exist? $pathExists" "DEBUG"

                # Scoring logic:
                # - For 'safe' programs, the path SHOULD exist. Result = 1 if it does.
                # - For malware/unauthorized, the path should NOT exist. Result = 1 if it does NOT.
                if ($program.Type -eq 'safe') {
                    if ($pathExists) { $result = 1 }
                } else { # For malware, manualmalware, Unauthorized, and Tempfiles
                    if (-not $pathExists) { $result = 1 } 
                }
                Log-Message "[STANDARD CHECK] Result score: $result" "DEBUG"
            }
            else {
                Log-Message "[STANDARD CHECK] 'Detection' path is empty in the CSV. Skipping." "DEBUG"
            }
        }
        # --- MARK: Password Policy Detection Logic ---
        elseif ($program.Type -eq 'PasswordPolicy') {
            $policyName = $program.Filename
            $expectedValue = $program.Detection
            $actualValue = $null

            # Map CSV Filename to the key from 'net accounts' output
            $policyKeyMap = @{
                'MinimumPasswordLength' = 'Minimum password length'
                'MaximumPasswordAge'    = 'Maximum password age (days)'
                'MinimumPasswordAge'    = 'Minimum password age (days)'
                'LockoutDuration'       = 'Lockout duration (minutes)'
                'LockoutThreshold'      = 'Lockout threshold'
                'LockoutWindow'         = 'Lockout observation window (minutes)'
                'ComplexityRequirements'= 'Password must meet complexity requirements'
            }

            if ($liveSecPol.ContainsKey($policyKeyMap[$policyName])) {
                $actualValue = $liveSecPol[$policyKeyMap[$policyName]]
                if ($actualValue -eq $expectedValue) {
                    $result = 1
                }
            }
            Log-Message "[POLICY CHECK] Policy: '$policyName'. Expected: '$expectedValue', Actual: '$actualValue'. Result: $result" "DEBUG"

        }
        # --- MARK: Scheduled Task Detection Logic ---
        elseif ($program.Type -eq 'ScheduledTask') {
            $taskName = $program.Detection
            $taskExists = $false
            try {
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    $taskExists = $true
                }
            } catch {}

            # Score is 1 if the task does NOT exist (i.e., it was removed).
            if (-not $taskExists) { $result = 1 }
            Log-Message "[SCHEDULED TASK CHECK] Task: '$taskName'. Exists: $taskExists. Result: $result" "DEBUG"
        }
        

        # --- MARK: Hardmode Software Detection Logic ---
        if ($program.Hardmode -eq 'yes') {
            Log-Message "[HARDMODE 1 CHECK] Hardmode is enabled. Starting detection." "DEBUG"
            
            if (-not ([string]::IsNullOrEmpty($program.HardmodeDetection))) {
                Log-Message "[HARDMODE 1 CHECK] Detection Method: $($program.HardmodeDetectionType), Path: $($program.HardmodeDetection)" "DEBUG"
                $hardmodePathExists = Test-Path -LiteralPath $program.HardmodeDetection
                Log-Message "[HARDMODE 1 CHECK] Does path exist? $hardmodePathExists" "DEBUG"

                # In hardmode, we assume the goal is to REMOVE the item, so score is 1 if it does NOT exist.
                if (-not $hardmodePathExists) {
                    $hardmoderesult = 1
                }
                Log-Message "[HARDMODE 1 CHECK] Result score: $hardmoderesult" "DEBUG"
            }
            else {
                Log-Message "[HARDMODE 1 CHECK] 'HardmodeDetection' path is empty. Skipping." "DEBUG"
            }
            
            # --- MARK: Second Hardmode Detection Logic ---
            if (-not ([string]::IsNullOrEmpty($program.Hardmode2Detection))) {
                Log-Message "[HARDMODE 2 CHECK] Detection Method: $($program.Hardmode2DetectionType), Path: $($program.Hardmode2Detection)" "DEBUG"
                $hardmode2PathExists = Test-Path -LiteralPath $program.Hardmode2Detection
                Log-Message "[HARDMODE 2 CHECK] Does path exist? $hardmode2PathExists" "DEBUG"

                if (-not $hardmode2PathExists) {
                    $hardmoderesult2 = 1
                }
                Log-Message "[HARDMODE 2 CHECK] Result score: $hardmoderesult2" "DEBUG"
            }
            else {
                Log-Message "[HARDMODE 2 CHECK] 'Hardmode2Detection' path is empty. Skipping." "DEBUG"
            }
        }
        
        # Create a custom PowerShell object with all the results for this program.
        $object = [PSCustomObject]@{
            FriendlyName          = $program.FriendlyName
            Type                  = $program.Type
            Result                = $result
            HardmodeResult        = $hardmoderesult
            Hardmode2Result       = $hardmoderesult2
            DetectionMethod       = $program.DetectionMethod
            Detection             = $program.Detection
            Hardmode              = $program.Hardmode
            HardmodeDetectionType = $program.HardmodeDetectionType
            HardmodeDetection     = $program.HardmodeDetection
            Hardmode2DetectionType= $program.Hardmode2DetectionType
            Hardmode2Detection    = $program.Hardmode2Detection
        }

        # Add the result object to our main array.
        $scoreResults += $object
    }
    catch {
        Log-Message "An unexpected error occurred while processing '$($program.FriendlyName)'. Error: $($_.Exception.Message). This program will be skipped." "ERROR"
    }
}

##############################################################################################
#endregion

##############################################################################################
# Region MARK: User and Group Scoring Logic
##############################################################################################
Log-Message "Starting user and group scoring..." "INFO"

# Import the list of Users to be checked.
try {
    $GeneratedUsers = Import-Csv $tempusersFile -ErrorAction Stop
    Log-Message "Successfully imported $($GeneratedUsers.Count) users from '$tempusersfile'." "INFO"
    
    # ADDED: Check if the imported CSV file is actually empty.
    if ($null -eq $GeneratedUsers -or $GeneratedUsers.Count -eq 0) {
        Log-Message "The file '$tempusersFile' was loaded, but it appears to be empty or only contain a header. Halting script." "ERROR"
        exit 1
    }
}
catch {
    Write-Error "Failed to import CSV file '$tempusersFile'. Please check if the file is valid."
    Write-Error "Error details: $($_.Exception.Message)"
    exit 1
}


foreach ($user in $GeneratedUsers) {
    try {
        Log-Message "Processing User: $($user.username)" "DEBUG"

        $result = 0
        $hardmodeResult = $null
        $hardmode2Result = $null

        Log-Message "[USER CHECK] User account check initiated for $($user.username)." "DEBUG"
        $userExists = Get-LocalUser -Name $user.username -ErrorAction SilentlyContinue
        $userExistsBool = $null -ne $userExists

        if ($userExistsBool) {
            if ($user.FakeAccount -eq '0') {
                $result = 1
                If ($user.WeakPassword -eq '1') {
                #Check the password reset date
                    $pwdLastSet = (Get-LocalUser -Name $user.username).PasswordLastSet
                    $daysSinceChange = (New-TimeSpan -Start $pwdLastSet -End (Get-Date)).Days
                    Log-Message "[WEAK PASSWORD CHECK] User '$($user.username)' password last set $daysSinceChange days ago." "DEBUG"
                    if ($daysSinceChange -le 30) {
                        $hardmode2Result = 1
                    } else {
                        $hardmode2Result = 0
                    }
                } else {
                    $hardmode2Result = $null
                }
            
            } elseif ($user.FakeAccount -eq '1') {
                $result = 0
            }

            # --- Group membership Detection Logic ---
            $groupExists = Get-LocalGroup -Name $user.groupname -ErrorAction SilentlyContinue
            $groupExistsBool = $null -ne $groupExists
            if ($groupExistsBool) {
                $isMember = Get-LocalGroupMember -Group $user.groupname -Member $user.username -ErrorAction SilentlyContinue
                $isMemberBool = $null -ne $isMember
                # If group exists and is not a fake group
                if ($user.FakeGroup -eq '0') {
                    if ($isMemberBool) {
                        $hardmodeResult = 1
                    } else {
                        $hardmodeResult = 0
                    }
                # If group exists and is a fake group    
                } elseif ($user.FakeGroup -eq '1') {
                    if (-not $isMemberBool) {
                        $hardmodeResult = 1
                    } else {
                        $hardmodeResult = 0
                    }
                }
                # If group exists and is a built-in group that users can be members of
                elseif ($user.FakeGroup -eq '3') {
                    # Built-in group logic: Just check if the user is a member.
                    if ($isMemberBool) {
                        $hardmodeResult = 1
                    } else {
                        $hardmodeResult = 0
                    }
                }
                # If group exists and is a built-in group that users should NOT be members of
                elseif ($user.FakeGroup -eq '4') {
                    # Built-in group logic: Just check if the user is a member.
                    if ($isMemberBool) {
                        $hardmodeResult = 0
                    } else {
                        $hardmodeResult = 1
                    }
                }
            } else {
                if ($user.Fakegroup -eq '1') {
                $hardmodeResult = 1 }
                Log-Message "[GROUP CHECK] Group '$($user.groupname)' does not exist." "DEBUG"
                #$hardmodeResult = 0
            }
        } else {
            if ($user.FakeAccount -eq '0') {
                $result = 0
                $hardmodeResult = 0
            } elseif ($user.FakeAccount -eq '1') {
                $result = 1
                $hardmodeResult = 1
            }
        }
        
        Log-Message "User: $($user.username), Fake Account: $($user.FakeAccount), Result: $result, HM1: $hardmodeResult, HM2: $hardmode2Result" "DEBUG"

        $object = [PSCustomObject]@{
            FriendlyName    = $user.username   
            Type            = "User"        
            DetectionMethod = $user.FakeAccount
            HardmodeResult  = $hardmodeResult
            Hardmode2Result = $hardmode2Result
            Result          = $result
            Hardmodedetection = $user.groupname
            HardmodedetectionType = if ($user.FakeGroup -eq '0') { 'Regular Group' }
                elseif ($user.FakeGroup -eq '1') { 'Fake Group' }
                elseif ($user.FakeGroup -eq '3') { 'Built-in Group' }
                elseif ($user.FakeGroup -eq '4') { 'No Membership Permitted' } 
                else { $null }
            Hardmode2detection = $user.Weakpassword
            Hardmode2detectionType = if ($user.WeakPassword -eq '1') { 'Weakpassword' } else { $null }
        }

        # Add the result object to our main array.
        $scoreResults += $object
    }
    catch {
        Log-Message "An unexpected error occurred while processing '$($user.username)'. Error: $($_.Exception.Message). This user will be skipped." "ERROR"
    }
}

#endregion

##############################################################################################
# Region MARK: Group Scoring Logic
##############################################################################################
Log-Message "Starting group scoring..." "INFO"

# Import the list of groups to be checked.
try {
    $GeneratedGroups = Import-Csv $tempgroupsFile -ErrorAction Stop
    Log-Message "Successfully imported $($Generatedgroups.Count) groups from '$tempgroupsFile'." "INFO"
    
    # ADDED: Check if the imported CSV file is actually empty.
    if ($null -eq $GeneratedGroups -or $GeneratedGroups.Count -eq 0) {
        Write-Error "The file '$tempgroupsFile' was loaded, but it appears to be empty or only contain a header."
        Write-Error "Please ensure it contains program data to be scored. Halting script."
        Stop-Transcript
        exit 1
    }
}
catch {
    Write-Error "Failed to import CSV file '$tempgroupsFile'. Please check if the file is valid."
    Write-Error "Error details: $($_.Exception.Message)"
    exit 1
}


foreach ($group in $GeneratedGroups) {
    try {
        Log-Message "Processing Group: $($group.Name)" "DEBUG"

        $result = 0
        
        Log-Message "[GROUP CHECK] Group check initiated for $($group.Name)." "DEBUG"
        # --- Group Detection Logic ---
        if ($group.FakeGroup -eq '0') {
            Log-Message "[GROUP CHECK] Regular group check for '$($group.Name)'." "DEBUG"
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } elseif ($group.FakeGroup -eq '1') {
            Log-Message "[GROUP CHECK] Fake group check for '$($group.Name)'." "DEBUG"
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 0
                } else {
                    $result = 1}            
        } elseif ($group.FakeGroup -eq '3') {
            Log-Message "[GROUP CHECK] Built-in group check for '$($group.Name)'." "DEBUG"
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } elseif ($group.FakeGroup -eq '4') {
            Log-Message "[GROUP CHECK] No membership permitted group check for '$($group.Name)'." "DEBUG"
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } else {
            Log-Message "[GROUP CHECK] Unknown FakeGroup value '$($group.FakeGroup)' for group '$($group.Name)'. Skipping." "WARN"
            continue
        }

        #Write-host "Group: $($group.Name)"
        #Write-host "Fake Group: $($group.Fakegroup)"
        $object = [PSCustomObject]@{
            FriendlyName    = $group.Name   
            Type            = "Group"        
            DetectionMethod = $group.Fakegroup
            Result          = $result
        }

        # Add the result object to our main array.
        $scoreResults += $object
    }
    catch {
        Log-Message "An unexpected error occurred while processing group '$($group.Name)'. Error: $($_.Exception.Message). This group will be skipped." "ERROR"
    }
}

#endregion



##############################################################################################
#region MARK: Firewall and Network Scoring
##############################################################################################
Log-Message "Starting firewall scoring process..." "INFO"

try {
    # Check the status of the main firewall profiles
    $profiles = Get-NetFirewallProfile -Name Domain, Private, Public -ErrorAction Stop
    
    # The check passes if all three profiles are enabled.
    $allEnabled = ($profiles | Where-Object { $_.Enabled -eq 'True' }).Count -eq 3
    
    $result = if ($allEnabled) { 1 } else { 0 }
    Log-Message "[FIREWALL CHECK] Firewall enabled on all profiles: $allEnabled. Result: $result" "DEBUG"

    $object = [PSCustomObject]@{
        FriendlyName = "Windows Firewall Enabled (All Profiles)"
        Type         = "Firewall"
        Result       = $result
    }
    $scoreResults += $object
}
catch {
    Log-Message "An unexpected error occurred while checking firewall status. Error: $($_.Exception.Message)" "ERROR"
}
#endregion

#region MARK: Final Score Export
# Export all collected results after all scoring sections are complete.
if ($null -ne $scoreResults -and $scoreResults.Count -gt 0) {
    Log-Message "Exporting $($scoreResults.Count) total results to '$scoreFile'..." "INFO"
    try {
        $scoreResults | Export-Csv -Path $scoreFile -NoTypeInformation -Force
        Log-Message "Final scoring export complete." "INFO"
    } catch {
        Log-Message "Failed to export final scores to '$scoreFile'. Error: $($_.Exception.Message)" "ERROR"
    }
} else {
    Log-Message "No results were generated to export. The output file will be empty." "WARN"
}
#endregion

# Close the "in progress" form before showing the final scorecard.
$progressForm.Close()
$progressForm.Dispose()


#MARK: GUI Score Display
# --- Create the Main Window ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Security Scorecard"
$form.Size = New-Object System.Drawing.Size(1000, 700)
$form.StartPosition = "CenterScreen"

# --- Create a Panel to Hold the Tables ---
$mainPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$mainPanel.Dock = "Fill"
$mainPanel.FlowDirection = "TopDown"
$mainPanel.AutoScroll = $true
$mainPanel.WrapContents = $false
$form.Controls.Add($mainPanel)

# --- Add Instructions at the Top ---
$instructionsLabel = New-Object System.Windows.Forms.Label
$instructionsLabel.Text = "Review each section carefully. Completed means passed, Incomplete means you missed something. Blank columns mean there was nothing else to check. Fake entries are highlighted."
$instructionsLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Italic)
$instructionsLabel.ForeColor = "DarkGreen"
$instructionsLabel.AutoSize = $true
$instructionsLabel.Margin = "10, 10, 10, 10"
$mainPanel.Controls.Add($instructionsLabel)


# --- Read and Process the Data ---
try {
    $data = Import-Csv -Path $scorefile
}
catch {
    [System.Windows.Forms.MessageBox]::Show("Error: '$scorefile' not found. Make sure the file path is correct.", "Error", "OK", "Error")
    exit
}

# --- Group all data by Type for display ---
$groupedData = $data | Group-Object -Property Type

# --- Helper Function to Add a Data Section ---
function Add-DataSection {
    param (
        [string]$sectionTitle,
        [array]$sectionData
    )

    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = $sectionTitle
    $headerLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = "Blue"
    $headerLabel.AutoSize = $true
    $headerLabel.Margin = "10, 10, 10, 0"
    $mainPanel.Controls.Add($headerLabel)

    $dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Size = New-Object System.Drawing.Size(940, 150)
    $dataGridView.Margin = "10, 5, 10, 10"
    $dataGridView.Font = New-Object System.Drawing.Font("Arial", 11)
    $dataGridView.DefaultCellStyle.Alignment = "MiddleCenter"
    $dataGridView.CellBorderStyle = "Single"
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.ReadOnly = $true
    $dataGridView.BackgroundColor = "White"
    $dataGridView.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
    $dataGridView.ColumnHeadersDefaultCellStyle.Alignment = "MiddleCenter"

# Change columns based on section type    
$lowerTitle = $sectionTitle.ToLower()

if ($lowerTitle.Contains("user")) {
    $dataGridView.Columns.Add("FriendlyName", "Username")
    $dataGridView.Columns.Add("Result", "Status")
    $dataGridView.Columns.Add("HardmodeResult", "Group Membership")
    $dataGridView.Columns.Add("Hardmode2Result", "Weak Password Fixed") # Placeholder for future use
}
elseif ($lowerTitle.Contains("group")) {
    $dataGridView.Columns.Add("FriendlyName", "Group Name")
    $dataGridView.Columns.Add("Result", "Status")
    $dataGridView.Columns.Add("HardmodeResult", " ")
    $dataGridView.Columns.Add("Hardmode2Result", " ") # Placeholder for future use
}
elseif ($lowerTitle.Contains("passwordpolicy")) {
    $dataGridView.Columns.Add("FriendlyName", "Policy Setting")
    $dataGridView.Columns.Add("Result", "Status")
    $dataGridView.Columns.Add("HardmodeResult", " ")
    $dataGridView.Columns.Add("Hardmode2Result", " ")
}
elseif ($lowerTitle.Contains("scheduledtask")) {
    $dataGridView.Columns.Add("FriendlyName", "Task Name")
    $dataGridView.Columns.Add("Result", "Removed")
    $dataGridView.Columns.Add("HardmodeResult", " ")
    $dataGridView.Columns.Add("Hardmode2Result", " ")
}
else {
    $dataGridView.Columns.Add("FriendlyName", "FriendlyName")
    $dataGridView.Columns.Add("Result", "Result")
    $dataGridView.Columns.Add("HardmodeResult", "Removed some leftovers")
    $dataGridView.Columns.Add("Hardmode2Result", "Removed more leftovers")
}

    foreach ($item in $sectionData) {
        # Determine if the current item is a "fake" one
        $isFakeItem = ($item.Type -eq "User" -or $item.Type -eq "Group") -and ($item.DetectionMethod -eq "1")

        $icon = if ($isFakeItem) { " decoy" } else { "" }
        $friendlyName = "$icon $($item.FriendlyName)"

        # Adjust the 'Result' text based on whether it's a fake item
        $resultText = if ($item.Result -eq "1") { "Completed" } elseif ($item.Result -eq "0") { "Incomplete" } else { $item.Result }
        if ($isFakeItem) {
            $resultText = if ($item.Result -eq "1") { "Removed" } else { "Not Removed" }
        }

        $hmResult = if ($item.HardmodeResult -eq "1") { "Completed" } elseif ($item.HardmodeResult -eq "0") { "Incomplete" } else { $item.HardmodeResult }
        $hm2Result = if ($item.Hardmode2Result -eq "1") { "Completed" } elseif ($item.Hardmode2Result -eq "0") { "Incomplete" } else { $item.Hardmode2Result }

        $dataGridView.Rows.Add($friendlyName, $resultText, $hmResult, $hm2Result) | Out-Null

        # Highlight the row if it's a fake item
        if ($isFakeItem) {
            $rowIndex = $dataGridView.Rows.Count - 1
            # If the fake item was successfully removed, highlight in green. Otherwise, pink.
            if ($item.Result -eq "1") {
                $dataGridView.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
            } else {
                $dataGridView.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightPink
            }
            $dataGridView.Rows[$rowIndex].Cells[0].Value = "[X] $($item.FriendlyName)" # Mark fake items with [X]
        }
    }

    $dataGridView.AutoSizeColumnsMode = "AllCells"
    $dataGridView.Columns["FriendlyName"].DefaultCellStyle.Alignment = "MiddleLeft"

    $totalHeight = $dataGridView.ColumnHeadersHeight
    foreach ($row in $dataGridView.Rows) {
        $totalHeight += $row.Height
    }
    $dataGridView.Height = $totalHeight + 2

    $mainPanel.Controls.Add($dataGridView)
}

# --- Add All Sections from Grouped Data ---
foreach ($group in $groupedData) {
    Add-DataSection -sectionTitle $group.Name.ToUpper() -sectionData $group.Group
}

# --- Calculate Totals ---
function Count-Checks {
    param ($items, $target)
    $count = 0
    foreach ($item in $items) {
        if ($item -eq $target) { $count++ }
    }
    return $count
}

$allItems = Import-Csv -Path $scorefile # Re-import all items to ensure totals are correct

$totalResult     = Count-Checks ($allItems | Select-Object -ExpandProperty Result) "1"
$totalHardmode   = Count-Checks ($allItems | Select-Object -ExpandProperty HardmodeResult) "1"
$totalHardmode2  = Count-Checks ($allItems | Select-Object -ExpandProperty Hardmode2Result) "1"
$totalScore      = $totalResult + $totalHardmode + $totalHardmode2

$totalMistakes   = Count-Checks ($allItems | Select-Object -ExpandProperty Result) "0" +
                   Count-Checks ($allItems | Select-Object -ExpandProperty HardmodeResult) "0" +
                   Count-Checks ($allItems | Select-Object -ExpandProperty Hardmode2Result) "0"

$totalCombined = $totalscore + $totalmistakes

# --- Add Total Label at the Bottom ---
$totalLabel = New-Object System.Windows.Forms.Label
$totalLabel.Text = "Completed Total Score: $totalScore/$totalCombined"
$totalLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$totalLabel.ForeColor = "DarkBlue"
$totalLabel.AutoSize = $true
$totalLabel.Margin = "10, 20, 10, 10"
$mainPanel.Controls.Add($totalLabel)




# --- Show the Final Window ---
$form.ShowDialog()

    Log-Message "--- Finished Score Card Generation ---" "INFO"
}

# This block ensures the script can be run directly.
# It defines a basic logging function and then calls the main function.
function Log-Message {
    param([string]$message, [string]$type = "INFO")
    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $logFile = Join-Path $logDir 'score.log'
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$type] $message" | Add-Content -Path $logFile
}

# Execute the main function of the script.
Invoke-OpenScoreCard -PSScriptRoot $PSScriptRoot
