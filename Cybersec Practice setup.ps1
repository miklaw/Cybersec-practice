param (
    # This parameter allows the script to accept a log file path when run directly.
    [string]$SetupLogFile
)
Write-Host "DEBUG: Cybersec Practice setup.ps1 script started."

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
    Write-Host "DEBUG: Assigned config values to script variables."
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
Get-ExcelSheetInfo -Path $sourceFile | Select-Object Name
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
        New-LocalGroup -Name $groupname
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
Set-Date -Date $passwordchangedate -ErrorAction Stop
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
            New-LocalGroup -Name $groupname
            Log-Message "Created group: $groupname" "INFO"
        }
        
        # Check if user already exists
        if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
            # Create the user account
            New-LocalUser -Name $username -Password $password -FullName $fullName
            Log-Message "Created user: $username" "INFO"
            # Add user to group
            Add-LocalGroupMember -Group $groupname -Member $username
            Log-Message "Added $username to group: $groupname" "INFO"
        } else {
            # Ensure that the user is a member of the group even if it already exists
            Add-LocalGroupMember -Group $groupname -Member $username -ErrorAction SilentlyContinue
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
#endregion

#region MARK: Safe program Prep
Log-Message "Preparing safe programs..." "DEBUG"
# Get all files in programs\safe
$programFiles = Get-ChildItem -Path $safeProgramsDir -File
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

# Export the list of installed programs to temp\installed.csv
$installedCsv = Join-Path $tempDir 'installed.csv'
Log-Message "Safe programs selected: $($installedList.Filename -join ', ')" "DEBUG"
$installedList | Export-Csv -Path $installedCsv -NoTypeInformation
#endregion

#region MARK: Unauthorized program Prep
Log-Message "Preparing unauthorized programs..." "DEBUG"
# Get all files in programs\unauthorized
$programFiles = Get-ChildItem -Path $unauthorizedProgramsDir -File
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

# Append the list of unauthorized programs to temp\installed.csv
Log-Message "Unauthorized programs selected: $($installedList.Filename -join ', ')" "DEBUG"
$installedList | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion

#region MARK: Malware program prep
Log-Message "Preparing malware programs..." "DEBUG"
# Get all files in programs\malware
$malwareFiles = Get-ChildItem -Path $malwareProgramsDir -File
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

# Append the list of malware programs to temp\installed.csv
$malwareList | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion

#region MARK: Manual malware program prep
Log-Message "Preparing manual malware..." "DEBUG"
# Get list of manual malware and install random based on $randommanualmalwarenumbers
$manualmalware = Get-ChildItem -Path $manualmalwareProgramsDir -Directory -Name 

# Select random manual malware folders
$RandomManualMalware = $manualmalware | Get-Random -Count $randommanualmalwarenumbers

# Get program information for installation and verification
$manualmalwareList = @()
foreach ($manualmalware in $RandomManualMalware) {
    $sourcePath = Join-Path $manualmalwareProgramsDir $manualmalware
    Log-Message "Manual malware selected: $manualmalware" "DEBUG"
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

# Append the list of malware programs to temp\installed.csv
$manualmalwareList | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion


#region MARK: Temp Files
# Get list of temp files for verification from programs.xlsx
Log-Message "Adding temp files for verification from $programsconfig" "INFO"
$tempverification = Import-Excel -Path $programsconfig -WorksheetName 'Tempfiles'
# Get list of manual malware and install random based on $randommanualmalwarenumbers

# Get program information for installation and verification
$tempfileList = @()
foreach ($tempfile in $tempverification) {
    Log-Message "Temp file verification added: $($tempfile.FriendlyName)" "DEBUG"
    $tempfileList += [PSCustomObject]@{
        OriginalPath = "Temporary Internet Files"
        Filename     = "Temporary Internet Files"
        Type         = "Tempfiles"
        Hardmode = $tempfile.Hardmode
        FriendlyName = $tempfile.FriendlyName
        Silent = ''
        Wait = ''
        DetectionMethod = $tempfile.DetectionMethod
        Detection = $tempfile.Detection
        HardmodeDetectionType = $tempfile.HardmodeDetectionType
        HardmodeDetection = $tempfile.HardmodeDetection
        Hardmode2DetectionType = $tempfile.Hardmode2DetectionType
        Hardmode2Detection = $tempfile.Hardmode2Detection
    }
}
Log-Message "Temp file list created with $($tempfileList.Count) items." "DEBUG"
# Append the list of malware programs to temp\installed.csv
$tempfilelist | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion

#region MARK: Enrich installed.csv with program config data
Log-Message "Enriching installed.csv with data from $programsconfig" "INFO"
# Import installed.csv and programs.xlsx
$installed = Import-Csv -Path $installedCsv
$programs = Import-Excel -Path $programsconfig -WorksheetName 'Software'

# Enrich installed list with Silent and Verification from programs.xlsx
foreach ($item in $installed) {
    $program = $programs | Where-Object { $_.Filename -eq $item.Filename }
    if ($program) {
        $item.FriendlyName = $program.FriendlyName
        $item.Hardmode = $program.Hardmode
        $item.Silent = $program.Silent
        $item.Wait = $program.Wait
        $item.DetectionMethod = $program.DetectionMethod
        $item.Detection = "$($program.Detection)"
        $item.HardmodeDetectionType = $program.HardmodeDetectionType
        $item.HardmodeDetection = "$($program.HardmodeDetection)"
        $item.Hardmode2DetectionType = $program.Hardmode2DetectionType
        $item.Hardmode2Detection = "$($program.Hardmode2Detection)"
    }
}
# Export the updated installed list back to installed.csv
$installed | Export-Csv -Path $installedCsv -NoTypeInformation
Log-Message "Enriched installed.csv with data from program config." "INFO"
#endregion

#region MARK: Sync system time
# Sync system time with internet time server.  This is used to detect the password change date for users.
Log-Message "Syncing system time with internet time server..." "INFO"
try {
    Start-Process w32tm -ArgumentList "/resync" -NoNewWindow -Wait
    Log-Message "System time synced successfully." "INFO"
} catch {
    Log-Message "Failed to sync system time. Please run this script with administrative privileges." "ERROR"
}
#endregion

#region Mark: Copy temp files to user profile
Log-Message "Copying temp files to user profile temp directories for verification..." "INFO"
Copy-Item -Path "$PSScriptRoot\Saltedfiles\*" -Destination "$env:APPDATA\Local\Microsoft\Edge\User Data\" -Recurse -Force

#endregion

#region MARK: Set Secpol standards for verification
Log-Message "Setting security policies for verification..." "INFO"
# This is section will generate random standards that will be used for verification
Write-Host "Setting security policies for verification"
# Random number between 8 and 12 for minimum password length
$minPasswordLength = Get-Random -Minimum 8 -Maximum 12
# Random password age limits
$maxPasswordAge = Get-Random -Minimum 30 -Maximum 90
$minPasswordAge = Get-Random -Minimum 1 -Maximum 7
# Random account lockout settings
$lockoutDuration = Get-Random -Minimum 5 -Maximum 30
$lockoutThreshold = Get-Random -Minimum 3 -Maximum 5
$lockoutWindow = Get-Random -Minimum 5 -Maximum 30

# Add data to a new line in $installedCsv
$secpolSettings = @"
# Security Policy Settings
MinimumPasswordLength = $minPasswordLength
MaximumPasswordAge = $maxPasswordAge
MinimumPasswordAge = $minPasswordAge
LockoutDuration = $lockoutDuration
LockoutThreshold = $lockoutThreshold
LockoutWindow = $lockoutWindow
"@
Add-Content -Path $installedCsv -Value $secpolSettings
Write-Host "Security policy settings added to $installedCsv"

# Disable Windows Firewall for testing purposes
Write-Host "Disabling Windows Firewall for testing purposes"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Log-Message "Windows Firewall disabled for all profiles." "WARN"



<# Set password policy to require complex passwords
secedit /export /cfg "$PSScriptRoot\temp\secpol.cfg" /quiet
# Modify the exported file to set password complexity
(Get-Content "$PSScriptRoot\temp\secpol.cfg") -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Set-Content "$PSScriptRoot\config\secpol.cfg"
# Import the modified security policy
secedit /import /cfg "$PSScriptRoot\config\secpol.cfg" /quiet
secedit /configure /db secedit.sdb /cfg "$PSScriptRoot\config\secpol.cfg" /quiet
Write-Host "Security policies set" 
#>



#endregion


#region MARK: Install Programs
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

# MARK: Install Unauthorized programs
Log-Message "Installing Unauthorized programs..." "INFO"
$installed = Import-Csv -Path $installedCsv
Foreach ($program in $installed) {
    if ($program.Type -eq 'unauthorized') {
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
#endregion


# Apply security policies that change password requirements, lockout policies, etc.

# Reset system date/time to current date/time
Log-Message "Resetting system date and time..." "INFO"
# Set the system date and time back to current (requires admin privileges)
try {
    # Start-Process w32tm -ArgumentList "/config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /reliable:yes /update"
    Set-Date -Date (Get-Date) -ErrorAction Stop
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
Write-Host "Generating README file on desktop"
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
    "Setup is complete.",
    "Environment is ready",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
)
exit
}

# When the script is run directly, the $PSScriptRoot automatic variable is available.
# We call the main function, passing the PSScriptRoot and any command-line parameters.
Invoke-CybersecSetup -PSScriptRoot $PSScriptRoot -SetupLogFile $PSBoundParameters['SetupLogFile']