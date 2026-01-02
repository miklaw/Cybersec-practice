Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop'
# Cybersecurity scoring preparation Script
# Created by Mike Law
# Creation Date: 2025-08-23
# Last updated: 2025-08-23 
# version 1.0
# Purpose: Scan for software packages and update the program spreadsheets.

#region MARK: Powershell modules
# Install NuGet package provider if not already installed
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -Force
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
#endregion

# MARK: Scan programs folder for .exe and .msi files and log to Programs.xlsx
# This script scans the 'programs' folder and its subfolders for .exe and .msi files
# and logs their filenames and folder names to an Excel file named Programs.xlsx
    # Define paths
    $programsPath = Join-Path $PSScriptRoot 'programs'
    $configPath = Join-Path $PSScriptRoot 'config\Programs.xlsx'

    # Find all .exe and .msi files in subfolders
    $files = Get-ChildItem -Path $programsPath -Recurse -Include *.exe, *.msi -File

    # Prepare data for Excel
    $data = foreach ($file in $files) {
        [PSCustomObject]@{
            Filename   = $file.Name
            FolderName = $file.Directory.BaseName
        }
    }

    # Export to Excel (append if file exists, else create)
    if (Test-Path $configPath) {
        $existing = Import-Excel -Path $configPath
        # Check if row 2 is empty (i.e., no data except headers)
        if ($existing.Count -lt 1) {
            # Overwrite everything starting at row 2 (i.e., clear and write fresh data)
            $data | Select-Object Filename, FolderName | Export-Excel -Path $configPath -WorksheetName 'Sheet1' -AutoSize -ClearSheet 3>$null
        } else {
            # Remove duplicates based on Filename and FolderName
            $newData = $data | Where-Object {
                $fn = $_.Filename
                $fd = $_.FolderName
                -not ($existing | Where-Object { $_.Filename -eq $fn -and $_.FolderName -eq $fd })
            }
            $allData = $existing + $newData
            if ($allData.Count -gt 0) {
                $allData | Select-Object Filename, FolderName | Export-Excel -Path $configPath -WorksheetName 'Sheet1' -AutoSize 3>$null
            } else {
                Write-Host "No new data to export to Excel."
            }
        }
    } else {
        if ($data.Count -gt 0) {
            $data | Select-Object Filename, FolderName | Export-Excel -Path $configPath -WorksheetName 'Sheet1' -AutoSize 3>$null
        } else {
            Write-Host "No data found to export to Excel."
        }
    }