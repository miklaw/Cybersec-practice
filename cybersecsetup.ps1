Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
# Cybersecurity Setup Script
# Created by Mike Law
# Creation Date: 2025-08-23
# Last updated: 2025-08-23 
# version 1.0
# Purpose: Automate the setup of a cybersecurity lab environment.

#TODO: Add $IsWindows and $Islinux checks to make the script cross platform
#TODO: Add Topmost window to hide all background windows during installation


##############################################################################################
#region MARK: Variables
##############################################################################################
# Define the number of users, groups, and programs to select
$randomusernumber = '6' # Number of random users to select from users.xlsx
$randomgroupnumber = '3' # Number of random groups to select from users.xlsx
$randomfakeusernumber = '1' # Number of random fake users to select from users.xlsx
$randomfakegroupnumber = '1' # Number of random fake groups to select from users.xlsx
$randomprogramnumbers = '2' # Number of random safe programs to select from programs\safe
$randommalwarenumbers = '2' # Number of random malware programs to select from programs\malware
$randommanualmalwarenumbers = '2' # Number of random manual malware programs to select
$randomunauthorizednumbers = '1' # Number of random unauthorized programs to select from programs\unauthorized
$numberofbuiltingroups = '1' # Number of built-in groups to restrict membership to

$passwordchangedate= "2025-01-01" # Date to set for last password change (format: YYYY-MM-DD)
#$accountexpdate= "2025-12-31" # Date to set for account expiration (format: YYYY-MM-DD)

# Define file paths
$tempDir = Join-Path $PSScriptRoot 'temp'
$Logfile = Join-Path $PSScriptRoot 'logs\setup.log'
$configsheets = 'config\users.xlsx' # Path to the Excel file containing user and group data
$sourceFile = Join-Path $PSScriptRoot $configsheets
$programsconfig = Join-Path $PSScriptRoot 'config\programs.xlsx'

$tempusersFile = Join-Path $tempDir 'tempusers.csv'
$tempgroupsFile = Join-Path $tempDir 'tempgroups.csv'
$manualmalwareProgramsDir = Join-Path $PSScriptRoot 'programs\manualmalware'
$malwareProgramsDir = Join-Path $PSScriptRoot 'programs\malware'
$safeProgramsDir = Join-Path $PSScriptRoot 'programs\safe'
$unauthorizedProgramsDir = Join-Path $PSScriptRoot 'programs\unauthorized'


##############################################################################################
#endregion
Start-Transcript -Path $Logfile


# Install Required software
if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\CybersecurityTraining' -Name 'SetupComplete' -ErrorAction SilentlyContinue) {
    Write-Host "Prequisites installed"
}
else {
    Write-Host "Installing Prerequisite software"
    Start-process -FilePath "$PSScriptRoot\programs\required\invoke-appdeploytoolkit.exe" -Wait -NoNewWindow
    Write-Host "Prerequisite software installed"
}


#endregion

# Mark: Import modules    
# Import the ImportExcel module so that we can read Excel files
Import-Module ImportExcel
    

#region MARK: Create temp directory and define file paths
# This script selects random user entries from an Excel file and saves them to a temporary CSV file for account creation
# Ensure temp directory exists
Write-Host "Creating temp directory at $tempDir"
if (-not (Test-Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory | Out-Null
}


# Remove existing temp file if it exists
if (Test-Path $tempusersFile) {
    Remove-Item $tempusersFile
}
#endregion

#region MARK: Select Random Users
Write-Host "Selecting random users from $sourceFile"
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
Write-Host "Selecting random groups from $sourceFile"
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
# Import FakeGroups from users.xlsx
$fakegroups = Import-Excel -Path $sourceFile -WorksheetName 'FakeGroups'

# Select random fake group
$fakerandomGroup = $fakegroups | Get-Random -Count $randomfakegroupnumber

# Append the selected fake group(s) to tempgroups.csv
$fakerandomGroup | Export-Csv -Path $tempgroupsFile -NoTypeInformation -Append
#endregion

#region MARK: Restrict built-in groups
Write-Host "Restricting  built-in groups from $sourceFile"
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
Write-Host "Assigning groups to users"
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
$groups = Import-Csv -Path $tempgroupsFile
foreach ($group in $groups) {
    $groupname = $group.Name
    # Check if group exists, if not, create it
    if (-not (Get-LocalGroup -Name $groupname -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $groupname
        Write-Host "Created group: $groupname"
    } else {
        Write-Host "Group $groupname already exists. Skipping."
    }
}
#endregion

#region MARK: Change date/time for verification of password change date

# This script changes the system date and time to a random date within the past year
# Calculate a random date within the past year      net user $env:USERNAME
Set-Date -Date $passwordchangedate -ErrorAction Stop
Get-Date
Write-Host "System date and time changed to: $passwordchangedate"

#endregion

#region MARK: Import User Accounts from tempusers.csv
Write-host "Creating user accounts from $tempusersFile"
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
            Write-Host "Created group: $groupname"
        }
        
        # Check if user already exists
        if (-not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
            # Create the user account
            New-LocalUser -Name $username -Password $password -FullName $fullName
            Write-Host "Created user: $username"
            # Add user to group
            Add-LocalGroupMember -Group $groupname -Member $username
            Write-Host "Added $username to group: $groupname"
        } else {
            # Ensure that the user is a member of the group even if it already exists
            Add-LocalGroupMember -Group $groupname -Member $username -ErrorAction SilentlyContinue
            Write-Host "User $username already exists. Skipping."
        }
    }
} else {
    Write-Host "Temporary users file not found: $tempUsersFile"
}
#endregion

#region MARK: Program prep
Write-Host "Selecting programs for installation"
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
Write-Host $installedlist
$installedList | Export-Csv -Path $installedCsv -NoTypeInformation
#endregion

#region MARK: Unauthorized program Prep
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
Write-Host $installedlist
$installedList | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion

#region MARK: Malware program prep
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
# Get list of manual malware and install random based on $randommanualmalwarenumbers
$manualmalware = Get-ChildItem -Path $manualmalwareProgramsDir -Directory -Name 

# Select random manual malware folders
$RandomManualMalware = $manualmalware | Get-Random -Count $randommanualmalwarenumbers

# Get program information for installation and verification
$manualmalwareList = @()
foreach ($manualmalware in $RandomManualMalware) {
    $sourcePath = Join-Path $manualmalwareProgramsDir $manualmalware
    Write-Host $manualmalware
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
Write-Host "Adding temp files for verification from $programsconfig"
$tempverification = Import-Excel -Path $programsconfig -WorksheetName 'Tempfiles'
# Get list of manual malware and install random based on $randommanualmalwarenumbers

# Get program information for installation and verification
$tempfileList = @()
foreach ($tempfile in $tempverification) {
    Write-Host $tempfile
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
Write-host "$tempfilelist"
# Append the list of malware programs to temp\installed.csv
$tempfilelist | Export-Csv -Path $installedCsv -NoTypeInformation -Append
#endregion

#region MARK: Enrich installed.csv with program config data
Write-host "Enriching installed.csv with data from $programsconfig"
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
Write-host "Enriched installed.csv"
#endregion

#region MARK: Sync system time
# Sync system time with internet time server.  This is used to detect the password change date for users.
Write-Host "Syncing system time with internet time server"
try {
    Start-Process w32tm -ArgumentList "/resync" -NoNewWindow -Wait
    Write-Host "System time synced successfully."
} catch {
    Write-Host "Failed to sync system time. Please run this script with administrative privileges."
}

#endregion

#region Mark: Copy temp files to user profile
Write-Host "Copying temp files to user profile temp directories for verification"
Copy-Item -Path "$PSScriptRoot\Saltedfiles\*" -Destination "$env:APPDATA\Local\Microsoft\Edge\User Data\" -Recurse -Force

#endregion

#region MARK: Set Secpol standards for verification
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

<#
#region MARK: Install Programs
# MARK: Install Safe programs
Write-Host "Installing selected programs"
$installed = Import-Csv -Path $installedCsv
Foreach ($program in $installed) {
    if ($program.Type -eq 'safe') {
        $programPath = $program.OriginalPath
        $wait = $program.Wait
        $silentArgs = $program.Silent
        if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
            $silentArgs = $silentArgs.Substring(1)
        }
        Write-Host "Installing $($program.Filename)..."
        if ($programPath -like '*.msi') {
            Write-Host "MSI installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                }else {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                }
        }else{
            Write-Host "Executable installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                }else {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs
                }
        }
        
        Write-Host "$($program.Filename) installation completed."
    }
}

# MARK: Install Manual malware programs
Write-Host "Installing selected manual malware programs"
$installed = Import-Csv -Path $installedCsv
Foreach ($program in $installed) {
    if ($program.Type -eq 'manualmalware') {
         $programPath = $program.OriginalPath
        $wait = $program.Wait
        $silentArgs = $program.Silent
        if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
            $silentArgs = $silentArgs.Substring(1)
        }
        Write-Host "Installing $($program.Filename)..."
        if ($programPath -like '*.msi') {
            Write-Host "MSI installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                }else {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                }
        }else{
            Write-Host "Executable installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                }else {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs
                }
        }
        
        Write-Host "$($program.Filename) installation completed."
    }
}

# MARK: Install Malware programs
Write-Host "Installing selected malware programs"
$installed = Import-Csv -Path $installedCsv
Foreach ($program in $installed) {
    if ($program.Type -eq 'malware') {
         $programPath = $program.OriginalPath
        $wait = $program.Wait
        $silentArgs = $program.Silent
        if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
            $silentArgs = $silentArgs.Substring(1)
        }
        Write-Host "Installing $($program.Filename)..."
        if ($programPath -like '*.msi') {
            Write-Host "MSI installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                }else {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                }
        }else{
            Write-Host "Executable installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                }else {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs
                }
        }
        
        Write-Host "$($program.Filename) installation completed."
    }
}

# MARK: Install Unauthorized programs
Write-Host "Installing Unauthorized programs"
$installed = Import-Csv -Path $installedCsv
Foreach ($program in $installed) {
    if ($program.Type -eq 'unauthorized') {
        $programPath = $program.OriginalPath
        $wait = $program.Wait
        $silentArgs = $program.Silent
        if ($silentArgs -is [string] -and $silentArgs.StartsWith("'")) {
            $silentArgs = $silentArgs.Substring(1)
        }
        Write-Host "Installing $($program.Filename)..."
        if ($programPath -like '*.msi') {
            Write-Host "MSI installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs" -Wait
                }else {
                    Start-Process "msiexec.exe" -ArgumentList "/I `"$programPath`" $silentArgs"
                }
        }else{
            Write-Host "Executable installer detected: $($program.Filename)"
                If ($wait -eq 'Wait') {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs -Wait
                }else {
                    Start-Process -FilePath $programPath -ArgumentList $silentArgs
                }
        }
        
        Write-Host "$($program.Filename) installation completed."
    }
}
Write-Host "Finished program installations"
#endregion


# Apply security policies that change password requirements, lockout policies, etc.

# Reset system date/time to current date/time
# Set the system date and time back to current (requires admin privileges)
<#try {
    # Start-Process w32tm -ArgumentList "/config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /reliable:yes /update"
    Set-Date -Date (Get-Date) -ErrorAction Stop
    #Write-Host "System date and time reset to current date and time."
} catch {
    Write-Host "Failed to reset system date and time. Please run this script with administrative privileges."
}
#>

#region MARK: README generator
$authorizedPrograms = $installed | Where-Object { $_.Type -eq 'safe' }
$authorizedusers = $randomUsers | Where-Object { $_.FakeAccount -eq '0' }
$authorizedgroups = $randomGroups | Where-Object { $_.FakeGroup -eq '0' }


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
$($authorizedusers | ForEach-Object { $_.Username } { $_.Password })

The following non-builtin groups have been authorized:
$($authorizedgroups | ForEach-Object { $_.Name })

The following programs have been authorized for installation:
$($authorizedPrograms | ForEach-Object { $_.FriendlyName })



"@

add-content -Path $readmePath -Value $readmecontent
Write-Host "README file generated at $readmePath"

#endregion
Stop-Transcript