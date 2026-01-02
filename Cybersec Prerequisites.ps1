# Install NuGet package provider if not already installed
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    # The -Confirm:$false parameter suppresses prompts, so SendKeys is not needed
    Install-PackageProvider -Name NuGet -Force -ForceBootstrap -Confirm:$false -SkipPublisherCheck
}
#Install required powershell modules
# Check if ImportExcel module is installed
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "ImportExcel module not found. Attempting to install..."
    try {
        Install-Module -Name ImportExcel -Force -AllowClobber -ErrorAction Stop
        Write-Host "ImportExcel module installed successfully."
    } catch {
        Write-Host "ERROR: Failed to install ImportExcel module. Error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error: Failed to install ImportExcel module. Please install it manually using: Install-Module -Name ImportExcel -Force", "Module Installation Error", "OK", "Error")
        exit
    }
} else {
    Write-Host "ImportExcel module found."
}

# Create Desktop shortcut
$DesktopPath = [System.IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "CyberSec Practice.lnk")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($DesktopPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-windowstyle hidden -executionpolicy bypass `"$PSScriptRoot\start.ps1`""
$Shortcut.WorkingDirectory = $PSScriptRoot
$Shortcut.Save()

# Set shortcut to run as administrator
$bytes = [System.IO.File]::ReadAllBytes($DesktopPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($DesktopPath, $bytes)

Write-Host "Desktop shortcut created successfully at $DesktopPath"

[System.Windows.Forms.MessageBox]::Show("Installed prerequisites.", "Prerequisites Installed", "OK", "INFORMATION")
