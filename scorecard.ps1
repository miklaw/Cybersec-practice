# Set the execution policy for the current process to avoid security errors.
# This is generally safe for scripts you trust.
try {
    Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
}
catch {
    Write-Warning "Could not set execution policy. This might cause issues on some systems."
    Write-Warning "Error: $($_.Exception.Message)"
}

# Cybersecurity Scoring Script
# Created by Mike Law
# Creation Date: 2025-08-23
# Last updated: 2025-08-23 
# version 1.0
# Purpose: Automate the setup of a cybersecurity lab environment.

#TODO: Add $IsWindows and $Islinux checks to make the script cross platform
#TODO: Add Topmost window to hide all background windows during installation


# Load the necessary .NET assemblies for creating a graphical user interface.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

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
Start-Transcript -Path $Logfile

# MARK: Score File prep
Write-Host "Preparing score files..." -ForegroundColor Green
if (Test-Path $tempusersFile) {
    Write-host "Found $tempusersFile"
}
else {
    Write-Host "File $tempusersFile not found. Please run the setup script first."
    exit
}
if (Test-path $tempgroupsFile) {
    Write-host "Found $tempgroupsFile"
}
else {
    Write-Host "File $tempgroupsFile not found. Please run the setup script first."
    exit
}
If (Test-path $scoreFile) {
    Write-host "Removing $scoreFile"
    Remove-item $scoreFile
}
else {
    Write-Host "File $scoreFile not found."  
}


##############################################################################################
#region MARK: Software Scoring Logic
##############################################################################################
Write-Host "Starting software scoring process..." -ForegroundColor Green

# Import the list of programs to be checked.
try {
    $installedPrograms = Import-Csv $installedProgramsFile -ErrorAction Stop
    Write-Host "Successfully imported $($installedPrograms.Count) programs from '$installedProgramsFile'."
    
    # ADDED: Check if the imported CSV file is actually empty.
    if ($null -eq $installedPrograms -or $installedPrograms.Count -eq 0) {
        Write-Error "The file '$installedProgramsFile' was loaded, but it appears to be empty or only contain a header."
        Write-Error "Please ensure it contains program data to be scored. Halting script."
        Stop-Transcript
        exit 1
    }
}
catch {
    Write-Error "Failed to import CSV file '$installedProgramsFile'. Please check if the file is valid."
    Write-Error "Error details: $($_.Exception.Message)"
    exit 1
}


# Initialize an empty array to hold the results of our checks.
$scoreResults = @()

# Loop through each program from the imported CSV file.
foreach ($program in $installedPrograms) {
    
    # ADDED: A try/catch block to handle errors for a single program without crashing the script.
    try {
        Write-Host "------------------------------------------------------------"
        Write-Host "Processing Program: $($program.FriendlyName) (Type: $($program.Type))"

        # Initialize result variables for the current program.
        $result = 0
        $hardmoderesult = $null
        $hardmoderesult2 = $null

        # --- MARK: Software Detection Logic ---
        if ($program.Type -in @('safe', 'malware', 'manualmalware', 'Unauthorized', 'Tempfiles')) {
            
            # ADDED: Check for null or empty path before testing.
            if (-not ([string]::IsNullOrEmpty($program.Detection))) {
                Write-Host "[STANDARD CHECK] Detection Method: $($program.DetectionMethod), Path: $($program.Detection)"
                
                # Check if the detection path actually exists.
                $pathExists = Test-Path -LiteralPath $program.Detection
                Write-Host "[STANDARD CHECK] Does path exist? $pathExists"

                # Scoring logic:
                # - For 'safe' programs, the path SHOULD exist. Result = 1 if it does.
                # - For malware/unauthorized, the path should NOT exist. Result = 1 if it does NOT.
                if ($program.Type -eq 'safe') {
                    if ($pathExists) { $result = 1 }
                }
                else { # For malware, manualmalware, Unauthorized
                    if (-not $pathExists) { $result = 1 }
                }
                Write-Host "[STANDARD CHECK] Result score: $result"
            }
            else {
                Write-Host "[STANDARD CHECK] 'Detection' path is empty in the CSV. Skipping."
            }
        }

        # --- MARK: Hardmode Software Detection Logic ---
        if ($program.Hardmode -eq 'yes') {
            Write-Host "[HARDMODE 1 CHECK] Hardmode is enabled. Starting detection."
            
            if (-not ([string]::IsNullOrEmpty($program.HardmodeDetection))) {
                Write-Host "[HARDMODE 1 CHECK] Detection Method: $($program.HardmodeDetectionType), Path: $($program.HardmodeDetection)"
                $hardmodePathExists = Test-Path -LiteralPath $program.HardmodeDetection
                Write-Host "[HARDMODE 1 CHECK] Does path exist? $hardmodePathExists"

                # In hardmode, we assume the goal is to REMOVE the item, so score is 1 if it does NOT exist.
                if (-not $hardmodePathExists) {
                    $hardmoderesult = 1
                }
                Write-Host "[HARDMODE 1 CHECK] Result score: $hardmoderesult"
            }
            else {
                Write-Host "[HARDMODE 1 CHECK] 'HardmodeDetection' path is empty. Skipping."
            }
            
            # --- MARK: Second Hardmode Detection Logic ---
            if (-not ([string]::IsNullOrEmpty($program.Hardmode2Detection))) {
                Write-Host "[HARDMODE 2 CHECK] Detection Method: $($program.Hardmode2DetectionType), Path: $($program.Hardmode2Detection)"
                $hardmode2PathExists = Test-Path -LiteralPath $program.Hardmode2Detection
                Write-Host "[HARDMODE 2 CHECK] Does path exist? $hardmode2PathExists"

                if (-not $hardmode2PathExists) {
                    $hardmoderesult2 = 1
                }
                Write-Host "[HARDMODE 2 CHECK] Result score: $hardmoderesult2"
            }
            else {
                Write-Host "[HARDMODE 2 CHECK] 'Hardmode2Detection' path is empty. Skipping."
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
        Write-Error "An unexpected error occurred while processing '$($program.FriendlyName)'."
        Write-Error "Error details: $($_.Exception.Message)"
        Write-Error "This program will be skipped. Processing will continue."
    }
}

# --- MARK: Export Software Results ---
# After the loop has finished processing all programs, export the entire results array to a CSV file.
if ($null -ne $scoreResults -and $scoreResults.Count -gt 0) {
    Write-Host "Exporting $($scoreResults.Count) results to '$scoreFile'..." -ForegroundColor Green
    $scoreResults | Export-Csv -Path $scoreFile -NoTypeInformation
    Write-Host "Scoring complete." -ForegroundColor Green
}
else {
    Write-Warning "No results were generated to export. The output file will be empty."
}

##############################################################################################
#endregion

##############################################################################################
# Region MARK: User and Group Scoring Logic
##############################################################################################
Write-Host "User and Group scoring section reached. No logic implemented yet."

# Import the list of Users to be checked.
try {
    $GeneratedUsers = Import-Csv $tempusersFile -ErrorAction Stop
    Write-Host "Successfully imported $($GeneratedUsers.Count) programs from '$tempusersfile'."
    
    # ADDED: Check if the imported CSV file is actually empty.
    if ($null -eq $GeneratedUsers -or $GeneratedUsers.Count -eq 0) {
        Write-Error "The file '$tempusersFile' was loaded, but it appears to be empty or only contain a header."
        Write-Error "Please ensure it contains program data to be scored. Halting script."
        Stop-Transcript
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
        Write-Host "------------------------------------------------------------"
        Write-Host "Processing User: $($user.username)"

        $result = 0
        $hardmodeResult = $null
        $hardmode2Result = $null

        Write-Host "[USER CHECK] User account check initiated."
        $userExists = Get-LocalUser -Name $user.username -ErrorAction SilentlyContinue
        $userExistsBool = $null -ne $userExists

        if ($userExistsBool) {
            if ($user.FakeAccount -eq '0') {
                $result = 1
                If ($user.WeakPassword -eq '1') {
                #Check the password reset date
                    $pwdLastSet = (Get-LocalUser -Name $user.username).PasswordLastSet
                    $daysSinceChange = (New-TimeSpan -Start $pwdLastSet -End (Get-Date)).Days
                    Write-Host "[WEAK PASSWORD CHECK] User '$($user.username)' password last set $daysSinceChange days ago."
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
                Write-Host "[GROUP CHECK] Group '$($user.groupname)' does not exist."
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
        
        Write-host "User: $user.username"
        Write-host "Fake Account: $user.FakeAccount"
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
        Write-Error "An unexpected error occurred while processing '$($user.username)'."
        Write-Error "Error details: $($_.Exception.Message)"
        Write-Error "This user will be skipped. Processing will continue."
    }
}

# Export all results after processing users
if ($null -ne $scoreResults -and $scoreResults.Count -gt 0) {
    Write-Host "Exporting $($scoreResults.Count) user/group results to '$scoreFile'..." -ForegroundColor Green
    $scoreResults | Export-Csv -Path $scoreFile -NoTypeInformation
    Write-Host "User and group scoring complete." -ForegroundColor Green
} else {
    Write-Warning "No user/group results were generated to export."
}
#endregion

##############################################################################################
# Region MARK: Group Scoring Logic
##############################################################################################
Write-Host "Group scoring section reached."

# Import the list of groups to be checked.
try {
    $GeneratedGroups = Import-Csv $tempgroupsFile -ErrorAction Stop
    Write-Host "Successfully imported $($Generatedgroups.Count) programs from '$tempgroupsFile'."
    
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
        Write-Host $group
        Write-Host "------------------------------------------------------------"
        Write-Host "Processing Group: $($group.Name)"

        $result = 0
        
        Write-Host "[Group CHECK] Group check initiated."
        # --- Group Detection Logic ---
        if ($group.FakeGroup -eq '0') {
            Write-Host "[Group CHECK] Regular group check for '$($group.Name)'."
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } elseif ($group.FakeGroup -eq '1') {
            Write-Host "[Group CHECK] Fake group check for '$($group.Name)'."
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 0
                } else {
                    $result = 1}            
        } elseif ($group.FakeGroup -eq '3') {
            Write-Host "[Group CHECK] Built-in group check for '$($group.Name)'."
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } elseif ($group.FakeGroup -eq '4') {
            Write-Host "[Group CHECK] No membership permitted group check for '$($group.Name)'."
            $GroupExists = Get-LocalGroup -Name $group.Name -ErrorAction SilentlyContinue
            $GroupExistsBool = $null -ne $GroupExists
                if ($GroupExistsBool) {
                    $result = 1
                } else {
                    $result = 0}
        } else {
            Write-Warning "[Group CHECK] Unknown FakeGroup value '$($group.FakeGroup)' for group '$($group.Name)'. Skipping."
            continue
        }

        Write-host "Group: $($group.Name)"
        Write-host "Fake Group: $($group.Fakegroup)"
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
        Write-Error "An unexpected error occurred while processing '$($user.username)'."
        Write-Error "Error details: $($_.Exception.Message)"
        Write-Error "This user will be skipped. Processing will continue."
    }
}

# Export all results after processing users
if ($null -ne $scoreResults -and $scoreResults.Count -gt 0) {
    Write-Host "Exporting $($scoreResults.Count) user/group results to '$scoreFile'..." -ForegroundColor Green
    $scoreResults | Export-Csv -Path $scoreFile -NoTypeInformation
    Write-Host "User and group scoring complete." -ForegroundColor Green
} else {
    Write-Warning "No user/group results were generated to export."
}
#endregion



Write-Host "Script execution finished at $(Get-Date)"
Stop-Transcript
# Mark: cookies and Cache Scoring
# Mark: Firewall and Network Scoring
# Mark: Services Scoring
# Mark: Scheduled Tasks Scoring

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
$instructionsLabel.Text = "Review each section carefully. Completed means passed, X means failed. Fake entries are highlighted."
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

# --- Filter for Fake Users and Fake Groups ---
$fakeUsers = $data | Where-Object { $_.Type -eq "User" -and $_.DetectionMethod -eq "1" }
$fakeGroups = $data | Where-Object { $_.Type -eq "Group" -and $_.DetectionMethod -eq "1" }

# --- Remove Fake entries from main data to avoid duplication ---
$data = $data | Where-Object {
    !($_.Type -eq "User" -and $_.DetectionMethod -eq "1") -and
    !($_.Type -eq "Group" -and $_.DetectionMethod -eq "1")
}

# --- Group the remaining data by Type ---
$groupedData = $data | Group-Object -Property Type

# --- Helper Function to Add a Data Section ---
function Add-DataSection {
    param (
        [string]$sectionTitle,
        [array]$sectionData,
        [bool]$isFake = $false
    )

    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = $sectionTitle
    $headerLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = if ($isFake) { "Red" } else { "Blue" }
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
    $accountColumn = if ($lowerTitle.Contains("fake")) { "Account Removed" } else { "Account Exists" }
    $dataGridView.Columns.Add("FriendlyName", "Username")
    $dataGridView.Columns.Add("Result", $accountColumn)
    $dataGridView.Columns.Add("HardmodeResult", "Group Membership")
    $dataGridView.Columns.Add("Hardmode2Result", "Weak Password Fixed") # Placeholder for future use
}
elseif ($lowerTitle.Contains("group")) {
    $groupColumn = if ($lowerTitle.Contains("fake")) { "Group Removed" } else { "Group Exists" }
    $dataGridView.Columns.Add("FriendlyName", "Group Name")
    $dataGridView.Columns.Add("Result", $groupColumn)
    $dataGridView.Columns.Add("HardmodeResult", " ")
    $dataGridView.Columns.Add("Hardmode2Result", " ") # Placeholder for future use
}
else {
    $dataGridView.Columns.Add("FriendlyName", "FriendlyName")
    $dataGridView.Columns.Add("Result", "Result")
    $dataGridView.Columns.Add("HardmodeResult", "Removed some leftovers")
    $dataGridView.Columns.Add("Hardmode2Result", "Removed more leftovers")
}

    foreach ($item in $sectionData) {
        $icon = if ($sectionTitle -eq "FAKE USERS") { "👤" } elseif ($sectionTitle -eq "FAKE GROUPS") { "👥" } else { "" }
        $friendlyName = "$icon $($item.FriendlyName)"
        $result = if ($item.Result -eq "1") { "Completed" } elseif ($item.Result -eq "0") { "Incomplete" }  else { $item.Result }
        $hmResult = if ($item.HardmodeResult -eq "1") { "Completed" } elseif ($item.HardmodeResult -eq "0") { "Incomplete" } else { $item.HardmodeResult }
        $hm2Result = if ($item.Hardmode2Result -eq "1") { "Completed" } elseif ($item.Hardmode2Result -eq "0") { "Incomplete" } else { $item.Hardmode2Result }

        $dataGridView.Rows.Add($friendlyName, $result, $hmResult, $hm2Result) | Out-Null

        if ($isFake) {
            $rowIndex = $dataGridView.Rows.Count - 1
            $dataGridView.Rows[$rowIndex].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightPink
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

# --- Add Fake Sections First ---
if ($fakeUsers.Count -gt 0) {
    Add-DataSection -sectionTitle "FAKE USERS" -sectionData $fakeUsers -isFake $true
}

if ($fakeGroups.Count -gt 0) {
    Add-DataSection -sectionTitle "FAKE GROUPS" -sectionData $fakeGroups -isFake $true
}

# --- Add Regular Sections ---
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

$allItems = $data + $fakeUsers + $fakeGroups

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

