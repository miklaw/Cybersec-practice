param (
    # This parameter allows the script to accept a log file path when run directly.
    [string]$SetupLogFile
)
# --- DEBUGGING ---
# Set to $true to skip the entire program installation section for faster testing.
$skipProgramInstalls = $false
Write-Host "DEBUG: Cybersec Practice setup.ps1 script started."
Write-Host "DEBUG: Defining Log-Message function..."

# Define a logging function that is available throughout the script.
# This ensures that when run standalone, it can log to the file passed by Start.ps1.
function Log-Message {
    param([string]$message, [string]$type = "INFO")
    # This function is self-contained for when the script is run directly.
    # It ensures the log directory and file exist before writing.
    $logDir = Join-Path $PSScriptRoot 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    # Use the passed LogFile parameter if available, otherwise default.
    $resolvedLogFile = if (-not [string]::IsNullOrEmpty($SetupLogFile)) { $SetupLogFile } else { Join-Path $logDir 'setup.log' }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$type] $message" | Add-Content -Path $resolvedLogFile
}

Write-Host "DEBUG: Finished defining Log-Message function..."
Write-Host "DEBUG: Defining Invoke-CybersecSetup function..."

function Invoke-CybersecSetup {
    param(
        [string]$PSScriptRoot,
        [string]$SetupLogFile
    )
    Write-Host "DEBUG: Invoke-CybersecSetup function entered."
    Log-Message "--- Starting Cybersec Practice Setup ---" "INFO"

# Load .NET assemblies for GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region MARK: Splash Screen
# Create and configure the splash screen form
$splashForm = New-Object System.Windows.Forms.Form
$splashForm.FormBorderStyle = 'None'
$splashForm.WindowState = 'Maximized'
$splashForm.TopMost = $true
$splashForm.BackColor = 'Black'
$splashForm.Text = 'Setup in Progress'

# Create and configure the label
$splashLabel = New-Object System.Windows.Forms.Label
$splashLabel.Text = 'Preparing the environment... Please wait.'
$splashLabel.Font = New-Object System.Drawing.Font('Arial', 24, [System.Drawing.FontStyle]::Bold)
$splashLabel.ForeColor = 'White'
$splashLabel.AutoSize = $true

# Center the label on the form
$splashForm.Add_Shown({
    $graphics = $splashForm.CreateGraphics()
    $labelSize = $graphics.MeasureString($splashLabel.Text, $splashLabel.Font)

    $splashLabel.Location = New-Object System.Drawing.Point(
        [int](($splashForm.ClientSize.Width - $labelSize.Width) / 2),
        [int](($splashForm.ClientSize.Height - $labelSize.Height) / 2)
    )
})

$splashForm.Controls.Add($splashLabel)
Write-Host "DEBUG: Showing splash screen."
# Show the splash screen without blocking the script
$splashForm.Show()
$splashForm.Activate()
$splashForm.Refresh()
[System.Windows.Forms.Application]::DoEvents()
#endregion

##############################################################################################
#region MARK: Load Configuration and Define Paths
##############################################################################################
# Load setup variables from the config file
Write-Host "DEBUG: Attempting to load setup configuration."
Log-Message "Loading setup configuration..." "INFO"
$scriptparamfile = Join-Path $PSScriptRoot 'config\scriptparams.cfg'

if (Test-Path $scriptparamfile) {
    Write-Host "DEBUG: Config file '$scriptparamfile' found. Attempting to load."
    # Load parameters from the config file
    $scriptparams = Get-Content -Path $scriptparamfile -Raw | ConvertFrom-StringData
    Log-Message "Successfully loaded parameters from '$scriptparamfile'." "INFO"
    #Write-Host "DEBUG: Loaded scriptparams: $((ConvertTo-Json -InputObject $scriptparams -Compress))"
    
    # Assign the loaded values to the script's variables
    # Ensure that if a key is missing from the config file, it doesn't cause an error.
    $randomusernumber = $scriptparams.randomusernumber
    $randomgroupnumber = $scriptparams.randomgroupnumber
    $randomfakeusernumber = $scriptparams.randomfakeusernumber
    $randomfakegroupnumber = $scriptparams.randomfakegroupnumber
    $randomprogramnumbers = $scriptparams.randomprogramnumbers
    $randommalwarenumbers = $scriptparams.randommalwarenumbers
    $randommanualmalwarenumbers = $scriptparams.randommanualmalwarenumbers
    $randomunauthorizednumbers = $scriptparams.randomunauthorizednumbers
    $numberofbuiltingroups = $scriptparams.numberofbuiltingroups
    $passwordchangedate = $scriptparams.passwordchangedate
    $randomscheduledtasks = $scriptparams.randomscheduledtasks
} else {
    Write-Host "ERROR: Config file '$scriptparamfile' not found. Exiting."
    Log-Message "Configuration file '$scriptparamfile' not found. The script cannot continue without its settings." "ERROR"
    [System.Windows.Forms.MessageBox]::Show("Error: Configuration file not found at '$scriptparamfile'. Please run the main Start.ps1 script to generate it.", "Configuration Error", "OK", "Error")
    exit
}

# Define file paths
if ([string]::IsNullOrEmpty($SetupLogFile)) {
    $SetupLogFile = Join-Path $PSScriptRoot 'logs\setup.log'
    Write-Host "DEBUG: SetupLogFile was empty, set to default: $SetupLogFile"
}
$tempDir = Join-Path $PSScriptRoot 'temp'
$configsheets = 'config\users.xlsx' # Path to the Excel file containing user and group data
$sourceFile = Join-Path $PSScriptRoot $configsheets
$programsconfig = Join-Path $PSScriptRoot 'config\programs.xlsx'

$tempusersFile = Join-Path $tempDir 'tempusers.csv'
$tempgroupsFile = Join-Path $tempDir 'tempgroups.csv'
$manualmalwareProgramsDir = Join-Path $PSScriptRoot 'programs\manualmalware'
$malwareProgramsDir = Join-Path $PSScriptRoot 'programs\malware'
$safeProgramsDir = Join-Path $PSScriptRoot 'programs\safe'
$unauthorizedProgramsDir = Join-Path $PSScriptRoot 'programs\unauthorized'


#endregion

# Mark: Import modules    
Log-Message "Importing required modules..." "DEBUG"
# Import the ImportExcel module so that we can read Excel files
Import-Module ImportExcel
    

#region MARK: Create temp directory and define file paths
# This script selects random user entries from an Excel file and saves them to a temporary CSV file for account creation
# Ensure temp directory exists.
Log-Message "Creating temp directory at $tempDir" "INFO"
if (-not (Test-Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory | Out-Null
}


# Remove existing temp file if it exists
if (Test-Path $tempusersFile) {
    Remove-Item $tempusersFile
}
#endregion

#region MARK: Select Random Users
Log-Message "Selecting random users from $sourceFile" "INFO"
# Import users from Excel
$users = Import-Excel -Path $sourceFile -WorksheetName 'Users'
# Get random users
$randomUsers = $users | Get-Random -Count $randomusernumber
# Export to CSV
$randomUsers | Export-Csv -Path $tempusersFile -NoTypeInformation
# Wait for the export to complete before continuing
while (-not (Test-Path $tempusersFile)) {
    Start-Sleep -Milliseconds 200
}
#endregion

#region MARK: Select Fake Users
Log-Message "Selecting random fake users from $sourceFile" "INFO"
# Import users from Excel
$fakeusers = Import-Excel -Path $sourceFile -WorksheetName 'FakeUsers'

# Get random fake users
$randomFakeUsers = $Fakeusers | Get-Random -Count $randomfakeusernumber

# Export to CSV
$randomFakeUsers | Export-Csv -Path $tempusersFile -NoTypeInformation -Force -Append
# Wait for the export to complete before continuing
while (-not (Test-Path $tempusersFile)) {
    Start-Sleep -Milliseconds 200
}
#endregion


#region MARK: Select Random Groups
Log-Message "Selecting random groups from $sourceFile" "INFO"
# Import RegularGroups from users.xlsx
$null = Get-ExcelSheetInfo -Path $sourceFile
$groups = Import-Excel -Path $sourceFile -WorksheetName 'RegularGroups'

# Select random groups
$randomGroups = $groups | Get-Random -Count $randomgroupnumber

# Get group names
$groupNames = $randomGroups

$groupNames | Export-Csv -Path $tempgroupsFile -NoTypeInformation
#endregion

#region MARK: Select Fake Groups
Log-Message "Selecting random fake groups from $sourceFile" "INFO"
# Import FakeGroups from users.xlsx
$fakegroups = Import-Excel -Path $sourceFile -WorksheetName 'FakeGroups'

# Select random fake group
$fakerandomGroup = $fakegroups | Get-Random -Count $randomfakegroupnumber

# Append the selected fake group(s) to tempgroups.csv
$fakerandomGroup | Export-Csv -Path $tempgroupsFile -NoTypeInformation -Append
#endregion

#region MARK: Restrict built-in groups
Log-Message "Restricting built-in groups from $sourceFile" "INFO"
# Import the CSV file
$groups = Import-Csv -Path $tempgroupsFile

# Find all rows where FakeGroup is '3'
$fakeGroup3 = $groups | Where-Object { $_.FakeGroup -eq '3' }

# If there are more than $numberofbuiltingroups variable, change the rest to '4'
if ($fakeGroup3.Count -gt $numberofbuiltingroups) {
    # Keep only the first 4 with value '3'
    $keep = $fakeGroup3 | Select-Object -First 4

    # Change the rest to '4'
    $change = $fakeGroup3 | Select-Object -Skip 4
    foreach ($item in $change) {
        $item.FakeGroup = '4'
    }
}

# Save the updated data back to CSV (optional)
$groups | Export-Csv -Path $tempgroupsFile -NoTypeInformation

#endregion

#region MARK: Assign groups to users
Log-Message "Assigning groups to users" "INFO"
# Import users and groups
$users = Import-Csv -Path $tempusersFile
$groups = Import-Csv -Path $tempgroupsFile

# Read group names and descriptions from $tempgroupsFile
$groupData = Import-Csv -Path $tempgroupsFile

# Assign group names and descriptions to users
# If there are more users than groups, cycle through group data from the top
for ($i = 0; $i -lt $users.Count; $i++) {
    $groupIndex = $i % $groupData.Count
    $users[$i].GroupName = $groupData[$groupIndex].Name
    $users[$i].FakeGroup = $groupData[$groupIndex].FakeGroup
}

# Export updated users with new group assignments and descriptions
$users | Export-Csv -Path $tempusersFile -NoTypeInformation
#endregion

#region MARK: Create groups if they don't exist
Log-Message "Creating local groups..." "INFO"
$groups = Import-Csv -Path $tempgroupsFile
foreach ($group in $groups) {
    $groupname = $group.Name
    # Check if group exists, if not, create it
    if (-not (Get-LocalGroup -Name $groupname -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $groupname | Out-Null
        Log-Message "Created group: $groupname" "INFO"
    } else {
        Log-Message "Group $groupname already exists. Skipping." "INFO"
    }
}
#endregion

#region MARK: Change date/time for verification of password change date
Log-Message "Changing system date for password age verification..." "INFO"
# This script changes the system date and time to a random date within the past year
# Calculate a random date within the past year      net user $env:USERNAME
Set-Date -Date $passwordchangedate -ErrorAction Stop | Out-Null
Log-Message "System date and time changed to: $(Get-Date)" "INFO"

#endregion

#region MARK: Import User Accounts from tempusers.csv
Log-Message "Creating user accounts from $tempusersFile" "INFO"
# This script creates user accounts based on the entries in tempusers.csv
# Define the path to the temporary users file
$tempUsersFile = Join-Path $PSScriptRoot 'temp\tempusers.csv'
if (Test-Path $tempUsersFile) {
    # Import users from CSV
    $users = Import-Csv -Path $tempUsersFile

    foreach ($user in $users) {
        $username = $user.Username
        $password = ConvertTo-SecureString $user.Password -AsPlainText -Force
        $fullName = $user.FullName
        $groupname = $user.Groupname
        $Weakpassword = $user.WeakPassword
        # Check if group exists, if not, create it
        if (-not (Get-LocalGroup -Name $groupname -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $groupname | Out-Null
            Log-Message "Created group: $groupname" "INFO"
        }
        
        # Check if user already exists
        if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
            # Create the user account
            New-LocalUser -Name $username -Password $password -FullName $fullName | Out-Null
            Log-Message "Created user: $username" "INFO"
            # Add user to group
            Add-LocalGroupMember -Group $groupname -Member $username | Out-Null
            Log-Message "Added $username to group: $groupname" "INFO"
        } else {
            # Ensure that the user is a member of the group even if it already exists
            Add-LocalGroupMember -Group $groupname -Member $username -ErrorAction SilentlyContinue | Out-Null
            Log-Message "User $username already exists. Skipping creation, ensuring group membership." "INFO"
        }
    }
} else {
    Log-Message "Temporary users file not found: $tempUsersFile" "WARN"
}
#endregion


#region MARK: Program prep
Log-Message "Selecting programs for installation..." "INFO"
# Remove temp\programs directory if it exists
if (Test-Path (Join-Path $tempDir 'programs')) {
    Remove-Item -Path (Join-Path $tempDir 'programs') -Recurse -Force
}

# Remove temp\installed.csv if it exists
if (Test-Path (Join-Path $tempDir 'installed.csv')) {
    Remove-Item -Path (Join-Path $tempDir 'installed.csv') -Force
}

# Ensure temp\programs directory exists
$tempProgramsDir = Join-Path $tempDir 'programs'
if (-not (Test-Path $tempProgramsDir)) {
    New-Item -Path $tempProgramsDir -ItemType Directory | Out-Null
}

# Initialize a master list to hold all programs and policies for the installed.csv
$allProgramsAndPolicies = @()
#endregion

#region MARK: Safe program Prep
Log-Message "Preparing safe programs..." "DEBUG"
# Get all files in programs\safe
$programFiles = Get-ChildItem -Path $safeProgramsDir -File

# Ensure $randomprogramnumbers is an integer
if ($randomprogramnumbers -is [string]) {
    $randomprogramnumbers = [int]$randomprogramnumbers
}
# Select random program files
$randomPrograms = $programFiles | Get-Random -Count $randomprogramnumbers
# Get program information for installation and verification
$installedList = @()
foreach ($program in $randomPrograms) {
    $installedList += [PSCustomObject]@{
        OriginalPath = $program.FullName
        Filename     = $program.Name
        Type         = 'safe'
        Hardmode = ''
        FriendlyName = ''
        Silent = ''
        Wait = ''
        DetectionMethod = ''
        Detection = ''
        HardmodeDetectionType = ''
        HardmodeDetection = ''
        Hardmode2DetectionType = ''
        Hardmode2Detection = ''
    }
}

# Add to the master list
$allProgramsAndPolicies += $installedList
Log-Message "Safe programs selected: $($installedList.FriendlyName -join ', ')" "DEBUG"
#endregion

#region MARK: Unauthorized program Prep
Log-Message "Preparing unauthorized programs..." "DEBUG"
# Get all files in programs\unauthorized
$programFiles = Get-ChildItem -Path $unauthorizedProgramsDir -File

# Ensure $randomunauthorizednumbers is an integer
if ($randomunauthorizednumbers -is [string]) {
    $randomunauthorizednumbers = [int]$randomunauthorizednumbers
}
# Select random program files
$randomUnauthorizedPrograms = $programFiles | Get-Random -Count $randomunauthorizednumbers
# Get program information for installation and verification
$installedList = @()
foreach ($program in $randomUnauthorizedPrograms) {
    $installedList += [PSCustomObject]@{
        OriginalPath = $program.FullName
        Filename     = $program.Name
        Type         = 'unauthorized'
        Hardmode = ''
        FriendlyName = ''
        Silent = ''
        Wait = ''
        DetectionMethod = ''
        Detection = ''
        HardmodeDetectionType = ''
        HardmodeDetection = ''
        Hardmode2DetectionType = ''
        Hardmode2Detection = ''
    }
}

# Add to the master list
$allProgramsAndPolicies += $installedList
Log-Message "Unauthorized programs selected: $($installedList.FriendlyName -join ', ')" "DEBUG"
#endregion

#region MARK: Malware program prep
Log-Message "Preparing malware programs..." "DEBUG"
# Get all files in programs\malware
$malwareFiles = Get-ChildItem -Path $malwareProgramsDir -File

# Ensure $randommalwarenumbers is an integer
if ($randommalwarenumbers -is [string]) {
    $randommalwarenumbers = [int]$randommalwarenumbers
}
# Select random malware files
$randomMalware = $malwareFiles | Get-Random -Count $randommalwarenumbers

# Get program information for installation and verification
$malwareList = @()
foreach ($malware in $randomMalware) {
    $malwareList += [PSCustomObject]@{
        OriginalPath = $malware.FullName
        Filename     = $malware.Name
        Type         = 'malware'
        Hardmode = ''
        FriendlyName = ''
        Silent = ''
        Wait = ''
        DetectionMethod = ''
        Detection = ''
        HardmodeDetectionType = ''
        HardmodeDetection = ''
        Hardmode2DetectionType = ''
        Hardmode2Detection = ''
    }
}

# Add to the master list
$allProgramsAndPolicies += $malwareList
Log-Message "Malware programs selected: $($malwareList.FriendlyName -join ', ')" "DEBUG"
#endregion

#region MARK: Manual malware program prep
Log-Message "Preparing manual malware..." "DEBUG"
# Get list of manual malware and install random based on $randommanualmalwarenumbers
$manualmalware = Get-ChildItem -Path $manualmalwareProgramsDir -Directory -Name 

# Ensure $randommanualmalwarenumbers is an integer
if ($randommanualmalwarenumbers -is [string]) {
    $randommanualmalwarenumbers = [int]$randommanualmalwarenumbers
}

# Select random manual malware folders
$RandomManualMalware = $manualmalware | Get-Random -Count $randommanualmalwarenumbers

# Get program information for installation and verification
$manualmalwareList = @()
foreach ($manualmalware in $RandomManualMalware) {
    $sourcePath = Join-Path $manualmalwareProgramsDir $manualmalware
    Log-Message "Manual malware selected: $manualmalware" "DEBUG" # Closing parenthesis was missing here
    $manualmalwareList += [PSCustomObject]@{
        OriginalPath = Join-Path $sourcePath '\Invoke-AppDeployToolkit.exe'
        Filename     = $manualmalware
        Type         = 'manualmalware'
        Hardmode = ''
        FriendlyName = ''
        Silent = ''
        Wait = ''
        DetectionMethod = ''
        Detection = ''
        HardmodeDetectionType = ''
        HardmodeDetection = ''
        Hardmode2DetectionType = ''
        Hardmode2Detection = ''
    }
}

# Add to the master list
$allProgramsAndPolicies += $manualmalwareList
Log-Message "Manual malware selected: $($manualmalwareList.FriendlyName -join ', ')" "DEBUG"
#endregion


#region MARK: Temp Files
# Get list of temp files for verification from programs.xlsx
Log-Message "Adding temp files for verification from $programsconfig" "INFO"

# Create the specific temporary file for removal check
$tempFilePath = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data\Default\Cache\CacheNotClear.txt"
$tempFileDir = Split-Path $tempFilePath -Parent
Log-Message "Creating temporary file for removal check: $tempFilePath" "INFO"

# Ensure the directory exists
if (-not (Test-Path $tempFileDir)) {
    New-Item -Path $tempFileDir -ItemType Directory -Force | Out-Null
}

# Create the file
Set-Content -Path $tempFilePath -Value "This file should be removed." -Force | Out-Null

# Add this file to the master list for scoring
$allProgramsAndPolicies += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'CacheNotClear.txt'
    Type         = 'Tempfiles'
    FriendlyName = 'Edge Cache File'
    DetectionMethod = 'FileExistence'
    Detection = $tempFilePath # The full path to the file to be detected/removed
    Hardmode = ''
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
#endregion

#region MARK: Generate Security Policy Settings
Log-Message "Generating random security policy settings..." "INFO"
# Random number between 8 and 12 for minimum password length
$minPasswordLength = Get-Random -Minimum 8 -Maximum 12
# Random password age limits
$maxPasswordAge = Get-Random -Minimum 30 -Maximum 90
$minPasswordAge = Get-Random -Minimum 1 -Maximum 7
# Random account lockout settings
$lockoutDuration = Get-Random -Minimum 5 -Maximum 30
$lockoutThreshold = Get-Random -Minimum 3 -Maximum 5
$lockoutWindow = Get-Random -Minimum 5 -Maximum 30

$secpolObjects = @()
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'MinimumPasswordLength'
    Type         = 'PasswordPolicy'
    Hardmode = ''
    FriendlyName = 'Minimum Password Length'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$minPasswordLength"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'MaximumPasswordAge'
    Type         = 'PasswordPolicy'
    Hardmode = ''
    FriendlyName = 'Maximum Password Age'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$maxPasswordAge"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'MinimumPasswordAge'
    Type         = 'PasswordPolicy'
    Hardmode = ''
    FriendlyName = 'Minimum Password Age'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$minPasswordAge"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'LockoutDuration'
    Type         = 'PasswordPolicy'
    Hardmode = ''
    FriendlyName = 'Account Lockout Duration'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$lockoutDuration"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'LockoutThreshold'
    Type         = 'PasswordPolicy'
    Hardmode = ''
    FriendlyName = 'Account Lockout Threshold'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$lockoutThreshold"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'LockoutWindow'
    Type         = 'PasswordPolicy'
    Hardmode     = ''
    FriendlyName = 'Lockout observation window'
    Silent = ''
    Wait = ''
    DetectionMethod = 'Policy'
    Detection = "$lockoutWindow"
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}
$secpolObjects += [PSCustomObject]@{
    OriginalPath = ''
    Filename     = 'ComplexityRequirements'
    Type         = 'PasswordPolicy'
    Hardmode     = ''
    FriendlyName = 'Password Complexity Requirements'
    Silent       = ''
    Wait         = ''
    DetectionMethod = 'Policy'
    Detection       = 'Enabled'
    HardmodeDetectionType = ''
    HardmodeDetection = ''
    Hardmode2DetectionType = ''
    Hardmode2Detection = ''
}

# Add the generated security policy objects to the master list
$allProgramsAndPolicies += $secpolObjects
Log-Message "Generated $($secpolObjects.Count) security policy objects." "DEBUG"
#endregion

#region MARK: Generate Malicious Scheduled Tasks
Log-Message "Generating malicious scheduled tasks..." "INFO"

# Define a pool of plausible but suspicious task details
$taskPool = @(
    @{ Name = "GoogleUpdateTaskMachineCore"; Description = "Keeps your Google software up to date."; Action = "calc.exe" },
    @{ Name = "Adobe Flash Player Updater"; Description = "Checks for updates to Adobe Flash Player."; Action = "notepad.exe" },
    @{ Name = "Java Update Scheduler"; Description = "Checks for new versions of Java."; Action = "powershell.exe"; Arguments = "-Command Start-Sleep -Seconds 30" },
    @{ Name = "SystemHealthCheck"; Description = "Monitors system health and performance."; Action = "cmd.exe"; Arguments = "/c echo System Health OK" },
    @{ Name = "OneDrive Standalone Updater"; Description = "Updates the OneDrive sync client."; Action = "explorer.exe" },
    @{ Name = "Microsoft Compatibility Telemetry"; Description = "Sends anonymous telemetry data to Microsoft."; Action = "control.exe" }
)

$scheduledTaskObjects = @()
try {
    # Ensure $randomscheduledtasks is an integer
    if ($randomscheduledtasks -is [string]) {
        $randomscheduledtasks = [int]$randomscheduledtasks
    }

    $selectedTasks = $taskPool | Get-Random -Count $randomscheduledtasks

    foreach ($task in $selectedTasks) {
        $taskAction = New-ScheduledTaskAction -Execute $task.Action -Argument $task.Arguments
        $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $task.Name -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Description $task.Description -Force | Out-Null
        
        $scheduledTaskObjects += [PSCustomObject]@{
            OriginalPath = ''
            Filename     = $task.Name
            Type         = 'ScheduledTask'
            Hardmode     = ''
            FriendlyName = $task.Name
            Silent       = ''
            Wait         = ''
            DetectionMethod = 'ScheduledTask'
            Detection       = $task.Name
        }
        Log-Message "Created scheduled task: $($task.Name)" "INFO"
    }
    $allProgramsAndPolicies += $scheduledTaskObjects
} catch {
    Log-Message "Failed to create scheduled tasks. Error: $($_.Exception.Message)" "ERROR"
}
#endregion

# Export the combined list of programs and policies to installed.csv for the first time
$installedCsv = Join-Path $tempDir 'installed.csv'
$allProgramsAndPolicies | Export-Csv -Path $installedCsv -NoTypeInformation
Log-Message "Initial export of all programs and policies to '$installedCsv'." "INFO"

#region MARK: Enrich installed.csv with program config data (excluding Tempfiles)
Log-Message "Enriching installed.csv with data from $programsconfig" "INFO"
# Import installed.csv and programs.xlsx
$installed = Import-Csv -Path $installedCsv
$programs = Import-Excel -Path $programsconfig -WorksheetName 'Software'

# Separate program entries from non-program entries (like policies and tasks) before enriching.
$nonProgramTypes = @('PasswordPolicy', 'ScheduledTask', 'Tempfiles')
$programsToEnrich = $installed | Where-Object { $_.Type -notin $nonProgramTypes }

# Enrich program list with Silent and Verification from programs.xlsx
foreach ($item in $programsToEnrich) {
    $programConfig = $programs | Where-Object { $_.Filename -eq $item.Filename }
    if ($programConfig) {
        $item.FriendlyName = $programConfig.FriendlyName
        $item.Hardmode = $programConfig.Hardmode
        $item.Silent = $programConfig.Silent
        $item.Wait = $programConfig.Wait
        $item.DetectionMethod = $programConfig.DetectionMethod
        $item.Detection = "$($programConfig.Detection)"
        $item.HardmodeDetectionType = $programConfig.HardmodeDetectionType
        $item.HardmodeDetection = "$($programConfig.HardmodeDetection)"
        $item.Hardmode2DetectionType = $programConfig.Hardmode2DetectionType
        $item.Hardmode2Detection = "$($programConfig.Hardmode2Detection)"
    }
}

# Recombine the enriched programs with the non-program entries that were set aside.
$nonProgramObjects = $installed | Where-Object { $_.Type -in $nonProgramTypes }
$installed = $programsToEnrich + $nonProgramObjects

# Export the final, enriched list (programs + policies) back to installed.csv
$installed | Export-Csv -Path $installedCsv -NoTypeInformation
Log-Message "Final enriched installed.csv (programs and policies) exported." "INFO"
#endregion




#region MARK: Sync system time
# Sync system time with internet time server.  This is used to detect the password change date for users.
Log-Message "Syncing system time with internet time server..." "INFO"
try {
    # Ensure the Windows Time service is running and configured for a more robust sync.
    if ((Get-Service -Name w32time).Status -ne 'Running') {
        Set-Service -Name w32time -StartupType Automatic -ErrorAction Stop
        Start-Service -Name w32time -ErrorAction Stop
        Log-Message "Windows Time service (w32time) was not running and has been started." "INFO"
    }
    
    # Configure to use a reliable source and resync. This is more robust than just /resync.
    w32tm.exe /config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /update | Out-Null
    w32tm.exe /resync /force | Out-Null

    Log-Message "System time synced successfully with time.windows.com." "INFO"
} catch {
    Log-Message "Failed to sync system time. This may require administrative privileges or an internet connection. Error: $($_.Exception.Message)" "ERROR"
}
#endregion

#region Mark: Copy temp files to user profile
Log-Message "Copying temp files to user profile temp directories for verification..." "INFO"
Copy-Item -Path "$PSScriptRoot\Saltedfiles\*" -Destination "$env:LOCALAPPDATA\Microsoft\Edge\User Data\" -Recurse -Force

#endregion

#region MARK: Disable Windows Firewall
Log-Message "Disabling Windows Firewall for testing purposes..." "INFO"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Log-Message "Windows Firewall disabled for all profiles." "WARN"

#endregion


#region MARK: Install Programs
if ($skipProgramInstalls) {
    Log-Message "Skipping program installations as per `$skipProgramInstalls` setting." "WARN"
} else {
    # MARK: Install Safe programs
    Log-Message "Starting program installation phase..." "INFO"
    $installed = Import-Csv -Path $installedCsv
    Foreach ($program in $installed) {
        if ($program.Type -eq 'safe') {
            $programPath = $program.OriginalPath
            $wait = $program.Wait
            $silentArgs = $program.Silent
            if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
                $silentArgs = $silentArgs.Substring(1)
            }
            Log-Message "Installing $($program.Filename)..." "INFO"
            if ($programPath -like '*.msi') {
                Log-Message "MSI installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                    }else {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                    }
            }else{
                Log-Message "Executable installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                    }else {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs
                    }
            }
            
            Log-Message "$($program.Filename) installation completed." "INFO"
        }
    }

    # MARK: Install Manual malware programs
    Log-Message "Installing selected manual malware programs..." "INFO"
    $installed = Import-Csv -Path $installedCsv
    Foreach ($program in $installed) {
        if ($program.Type -eq 'manualmalware') {
             $programPath = $program.OriginalPath
            $wait = $program.Wait
            $silentArgs = $program.Silent
            if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
                $silentArgs = $silentArgs.Substring(1)
            }
            Log-Message "Installing $($program.Filename)..." "INFO"
            if ($programPath -like '*.msi') {
                Log-Message "MSI installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                    }else {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                    }
            }else{
                Log-Message "Executable installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                    }else {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs
                    }
            }
            
            Log-Message "$($program.Filename) installation completed." "INFO"
        }
    }

    # MARK: Install Malware programs
    Log-Message "Installing selected malware programs..." "INFO"
    $installed = Import-Csv -Path $installedCsv
    Foreach ($program in $installed) {
        if ($program.Type -eq 'malware') {
             $programPath = $program.OriginalPath
            $wait = $program.Wait
            $silentArgs = $program.Silent
            if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
                $silentArgs = $silentArgs.Substring(1)
            }
            Log-Message "Installing $($program.Filename)..." "INFO"
            if ($programPath -like '*.msi') {
                Log-Message "MSI installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                    }else {
                        Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                    }
            }else{
                Log-Message "Executable installer detected: $($program.Filename)" "DEBUG"
                    If ($wait -eq 'Wait') {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                    }else {
                        Start-Process -FilePath $programPath -ArgumentList $silentArgs
                    }
            }
            
            Log-Message "$($program.Filename) installation completed." "INFO"
        }
    }
    Log-Message "Finished program installations." "INFO"
}
#endregion

#region MARK: Scan for Windows Updates
Log-Message "Scanning for Windows Updates (this does not install them)..." "INFO"
try {
    # Use the PSWindowsUpdate module if available, as it's a reliable method.
    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
        Log-Message "Using PSWindowsUpdate module to scan for updates." "DEBUG"
        Get-WindowsUpdate -ScanOnly -ErrorAction Stop | Out-Null
    } else {
        # Fallback to UsoClient if the module is not present.
        Log-Message "PSWindowsUpdate module not found. Using UsoClient.exe to initiate a scan." "DEBUG"
        Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartScan" -Wait -NoNewWindow
        Log-Message "UsoClient.exe scan initiated." "INFO"
    }
    Log-Message "Windows Update scan completed. This action updates the 'last checked' time." "INFO"
} catch {
    Log-Message "Failed to check for Windows Updates. Error: $($_.Exception.Message)" "ERROR"
}
#endregion

# Apply security policies that change password requirements, lockout policies, etc.

# Reset system date/time to current date/time
Log-Message "Resetting system date and time..." "INFO"
# Set the system date and time back to current (requires admin privileges)
try {
    # Start-Process w32tm -ArgumentList "/config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /reliable:yes /update"
    Set-Date -Date (Get-Date) -ErrorAction Stop | Out-Null
    Log-Message "System date and time reset to current date and time." "INFO"
} catch {
    Log-Message "Failed to reset system date and time. Please run this script with administrative privileges." "ERROR"
}


#region MARK: README generator
$allTempUsers = Import-Csv -Path $tempusersFile # Re-import to get the full list
$authorizedPrograms = $installed | Where-Object { $_.Type -eq 'safe' }
$authorizedusers = $allTempUsers | Where-Object { $_.FakeAccount -eq '0' }
$authorizedgroups = $randomGroups | Where-Object { $_.FakeGroup -eq '0' }

# Pre-format the lists into strings to ensure correct expansion in the here-string
$userList = ($authorizedusers | ForEach-Object { "  - $($_.Username): $($_.Password)" } | Out-String).Trim()
$groupList = ($authorizedgroups | ForEach-Object { "  - $($_.Name)" } | Out-String).Trim()
$programList = ($authorizedPrograms | ForEach-Object { "  - $($_.FriendlyName)" } | Out-String).Trim()


Log-Message "Generating README file on desktop..." "INFO"
$desktop = [Environment]::GetFolderPath("Desktop")
$readmePath = Join-Path $desktop 'README.txt'
$readmecontent = @"
Cybersecurity Lab Setup Complete
This system has been configured for cybersecurity training purposes. 

Scenario:
You have been hired as a cybersecurity consultant to assess and improve the security posture of this system. 
Your tasks include identifying vulnerabilities, analyzing user accounts and groups, evaluating installed software, and implementing security best practices.

The following users have been authorized for use on this system and here are their passwords.  
If passwords are weak, you must identify and change them to meet complexity requirements:
$userList

The following non-builtin groups have been authorized:
$groupList

The following programs have been authorized for installation:
$programList

The company demands that a password policy be enforced.  The current password policy settings are as follows:
- Minimum Password Length: $minPasswordLength characters
- Maximum Password Age: $maxPasswordAge days
- Minimum Password Age: $minPasswordAge days
- Lockout Duration: $lockoutDuration Minutes
- Lockout Threshold: $lockoutThreshold attempts
- Lockout Window: $lockoutWindow Minutes

"@

Set-Content -Path $readmePath -Value $readmecontent
Log-Message "README file generated at $readmePath" "INFO"

#endregion

# Close the splash screen
$splashForm.Close()
    Write-Host "DEBUG: Invoke-CybersecSetup function finished."
    Log-Message "--- Finished Cybersec Practice Setup ---" "INFO"
    # Show completion message first, so it appears on top of the splash screen.
[System.Windows.Forms.MessageBox]::Show(
    "Setup is complete.", "Environment is ready", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
#exit 
}


# When the script is run directly, the $PSScriptRoot automatic variable is available.
# We call the main function, passing the PSScriptRoot and any command-line parameters.
Invoke-CybersecSetup -PSScriptRoot $PSScriptRoot -SetupLogFile $SetupLogFile