# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# Increase the buffer size
$bufferHeight = 9999

$console = [System.Console]::BufferHeight = $bufferHeight

Write-Host "Buffer size increased to Height: $bufferHeight" -ForegroundColor Green

# Initialize reference variables to store original ACL and owner
[ref]$originalAcl = $null
[ref]$originalOwner = $null

# Function to take ownership of the folder or file
function Take-Ownership {
    param (
        [parameter(Mandatory=$true)][string]$Path,
        [ref]$OriginalAcl,
        [ref]$OriginalOwner
    )

    try {
        # Backup the current owner and ACLs
        $OriginalAcl.Value = Get-Acl -Path $Path
        $OriginalOwner.Value = $OriginalAcl.Value.Owner

        # Define a new owner (e.g., the current user)
        $newOwner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

        # Set the owner of the folder or file
        $acl = Get-Acl -Path $Path
        $acl.SetOwner($newOwner)
        Set-Acl -Path $Path -AclObject $acl

        # Add full control to the current user
        if (Test-Path $Path -PathType Container) {
            # Folder (container)
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($newOwner, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        } else {
            # File
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($newOwner, "FullControl", "None", "None", "Allow")
        }
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $Path -AclObject $acl

        Write-Output "Ownership taken and full control granted for $Path."
    } catch {
        Write-Error "An error occurred while taking ownership: $_"
        throw
    }
}

# Function to restore the original ownership and ACLs
function Restore-Ownership {
    param (
        [parameter(Mandatory=$true)][string]$Path,
        [parameter(Mandatory=$true)]$OriginalAcl,
        [parameter(Mandatory=$true)]$OriginalOwner
    )

    try {
        # Convert the original owner to an IdentityReference object
        $originalOwnerIdentity = [System.Security.Principal.NTAccount]::new($OriginalOwner.Value)
        
        # Restore the original owner
        $acl = Get-Acl -Path $Path
        $acl.SetOwner($originalOwnerIdentity)
        Set-Acl -Path $Path -AclObject $acl

        # Restore the original ACLs
        Set-Acl -Path $Path -AclObject $OriginalAcl.Value

        Write-Output "Original owner and ACLs restored for $Path."
    } catch {
        Write-Error "An error occurred while restoring ownership: $_"
    }
}

# Function to get the free space on the Windows drive
function Get-FreeSpace {
    param (
        [string]$driveRoot
    )
    $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -eq $driveRoot }
    return $drive.Free
}

# Get the drive where Windows is installed
$windowsDriveRoot = ([System.IO.Path]::GetPathRoot($env:SystemRoot))

# Capture initial free space
$initialFreeSpaceBytes = Get-FreeSpace -driveRoot $windowsDriveRoot
$initialFreeSpaceGB = [math]::round($initialFreeSpaceBytes / 1GB, 2)
$initialFreeSpaceMB = [math]::round($initialFreeSpaceBytes / 1MB, 2)

Write-Host "Initial Free Space: $initialFreeSpaceGB GB ($initialFreeSpaceMB MB) ($initialFreeSpaceBytes Bytes)" -ForegroundColor Green

function Remove-StateFlags0112 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$rootKey,

        [Parameter(Mandatory = $true)]
        [string]$subKey
    )

    # Combine rootKey and subKey for full path
    $fullPath = "$rootKey\$subKey"

    # Get the full registry path
    $regPath = "Registry::$fullPath"

    # Function to recursively remove StateFlags0112
    function Recurse-RemoveStateFlags0112 {
        param($keyPath)

        # Check if the key path exists
        if (Test-Path $keyPath) {
            # Get subkeys
            $subKeyNames = Get-ChildItem -Path $keyPath -Name
            foreach ($subKeyName in $subKeyNames) {
                $subKeyPath = Join-Path -Path $keyPath -ChildPath $subKeyName
                Recurse-RemoveStateFlags0112 -keyPath $subKeyPath
            }

            # Remove the StateFlags0112 value if it exists
            if (Test-Path $keyPath) {
                if (Get-ItemProperty -Path $keyPath -Name 'StateFlags0112' -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $keyPath -Name 'StateFlags0112' -Force
                    Write-Output "Removed 'StateFlags0112' from $keyPath"
                }
            }
        }
    }

    # Start recursion
    Recurse-RemoveStateFlags0112 -keyPath $regPath
}

Write-Host "Removing the current Windows Clean Manager state flags" -ForegroundColor Green
Remove-StateFlags0112 -rootKey "HKEY_LOCAL_MACHINE" -subKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

function Add-StateFlags0112 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootKey,

        [Parameter(Mandatory = $true)]
        [string]$SubKey,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        [int]$ValueData
    )

    # Combine the root key and subkey to get the full path
    $fullPath = "$RootKey\$SubKey"
    $regPath = "Registry::$fullPath"

    # Check if the registry key exists
    if (-not (Test-Path $regPath)) {
        # Create the registry key if it does not exist
        New-Item -Path $regPath -Force | Out-Null
        Write-Output "Created registry key: $fullPath"
    } else {
        Write-Output "Registry key already exists: $fullPath"
    }

    # Set or update the DWORD value
    Set-ItemProperty -Path $regPath -Name $ValueName -Value $ValueData -Type DWord -Force
    Write-Output "Set '$ValueName' to $ValueData in $fullPath"
}

# https://winaero.com/cleanmgr-exe-command-line-arguments-in-windows-10/
Write-Host "Adding state flags for Windows Clean Manager" -ForegroundColor Green
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Sync Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" -ValueName "StateFlags0112" -ValueData 2
Add-StateFlags0112 -RootKey "HKEY_LOCAL_MACHINE" -SubKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" -ValueName "StateFlags0112" -ValueData 2

# Clear the print queue
try {
    Write-Host "Clear the print queue" -ForegroundColor Green
    # Stop the Print Spooler service
    Write-Output "Stopping the Print Spooler service..."
    Stop-Service -Name "spooler" -Force -ErrorAction Stop

    # Define the path to the print queue directory
    $printerPath = "$env:SystemRoot\System32\spool\PRINTERS"

    # Delete the print queue files
    Write-Output "Deleting print queue files..."
    Remove-Item -Path "$printerPath\*.spl" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$printerPath\*.shd" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$printerPath\*.tmp" -Force -ErrorAction SilentlyContinue

    # Start the Print Spooler service
    Write-Output "Starting the Print Spooler service..."
    Start-Service -Name "spooler" -ErrorAction Stop

    Write-Output "Print queue cleared successfully."
} catch {
    Write-Error "An error occurred: $_"
}

# Remove Dotnet CLI telemetry
$dotnetCliTelemetry = "$env:USERPROFILE\.dotnet\TelemetryStorageService"
if (Test-Path -Path "$dotnetCliTelemetry") {
    Write-Host "Removing Dotnet cli telemetry" -ForegroundColor Green
    # Remove the directory and all its contents
    Remove-Item -Path $dotnetCliTelemetry -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output "Deleted directory and all contents at: $dotnetCliTelemetry"
}

# Removing .etl files
# https://www.partitionwizard.com/partitionmanager/free-up-ssd-space-consumed-with-etl-files.html
# ETL files are log files that contain event logs generated by Microsoft Operating System Kernel. These log files include application and system-level errors, warnings, and other events data
# Define the paths to process
$etlPaths = @("$env:WINDIR", "$env:userprofile\Appdata\Local\Diagnostics", "$env:userprofile\Appdata\Local\Microsoft", "$env:userprofile\Appdata\Roaming\Microsoft", "$env:ProgramData\USOShared", "$env:ProgramData\PLUG", "$env:ProgramData\Microsoft")
foreach ($path in $etlPaths) {
    if (Test-Path -Path "$path") {
        Write-Host "Removing .etl files from $path" -ForegroundColor Green
        # Get all .etl files recursively and delete them
        Get-ChildItem -Path $path -Recurse -Filter *.etl -ErrorAction SilentlyContinue -ErrorVariable myErrors | ForEach-Object {
            try {
                Write-Output "Processing: $($_.FullName)"
                #$folderPath = Split-Path $($_.FullName) -Parent
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch [System.UnauthorizedAccessException] {
                # Handles specific UnauthorizedAccessException
                Write-Output "UnauthorizedAccessException for: $($_.FullName)"
            } catch {
                # Handles other exceptions
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                try {
                    # Take ownership of the file
                    Take-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                    Remove-Item -Path $($_.TargetObject) -Force -ErrorAction Stop
                    Write-Host "Deleted: $($_.TargetObject)" -ForegroundColor Yellow
                } catch {
                    # Handles other exceptions
                    Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                } finally {
                    # Restore the original ownership and ACLs if file still exists
                    if ($originalAcl -ne $null -and $originalOwner -ne $null) {
                        if (Test-Path "$($_.TargetObject)" -PathType Leaf) {
                            Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                        }
                    } else {
                        Write-Warning "Original ACL and owner information is missing, cannot restore."
                    }
                }
            }
        }

        # Check for and report any errors captured in the ErrorVariable
        if ($myErrors) {
            Write-Host "Errors encountered:" -ForegroundColor Yellow
            $myErrors | ForEach-Object {
                Write-Host "Error for: $($_.TargetObject)" -ForegroundColor Red
                #Write-Host "Message: $($_.Exception.Message)"
                if (Test-Path -Path "$($_.TargetObject)" -PathType Container) {
                    try {
                        # Take ownership of the folder
                        Take-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner

                        # Get all .etl files recursively and delete them
                        Get-ChildItem -Path "$($_.TargetObject)" -Recurse -Filter *.etl -ErrorAction SilentlyContinue -ErrorVariable myErrors | ForEach-Object {
                            try {
                                Write-Output "Processing: $($_.FullName)"
                                #$folderPath = Split-Path $($_.FullName) -Parent
                                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
                            } catch [System.UnauthorizedAccessException] {
                                # Handles specific UnauthorizedAccessException
                                Write-Output "UnauthorizedAccessException for: $($_.FullName)"
                            } catch {
                                # Handles other exceptions
                                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                            }
                        }
                    } catch {
                        Write-Error "An error occurred during the operation: $_"
                    } finally {
                        # Restore the original ownership and ACLs
                        if ($originalAcl -ne $null -and $originalOwner -ne $null) {
                            Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                        } else {
                            Write-Warning "Original ACL and owner information is missing, cannot restore."
                        }
                    }
                }
            }
        }
        Write-Output "All .etl files in the specified paths have been processed."
    } else {
        Write-Output "Path does not exist: $path"
    }
}

# Define the path to the Temp directory
$tempPath = "$env:TEMP"

if (Test-Path -Path "$tempPath") {
    Write-Host "Removing temp files #1" -ForegroundColor Green
    # Get all files in the Temp directory and its subdirectories
    # Filter files older than 3 days and delete them
    Get-ChildItem -Path $tempPath -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Output "All files older than 3 days in $tempPath have been processed."
}

# Define the path to the Temp directory
$windirTempPath = "$Env:WinDir\Temp"

if (Test-Path -Path "$windirTempPath") {
    Write-Host "Removing temp files #2" -ForegroundColor Green
    # Get all files in the Temp directory and its subdirectories
    # Filter files older than 3 days and delete them
    Get-ChildItem -Path $windirTempPath -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Output "All files older than 3 days in $windirTempPath have been processed."
}

# Define the path to the Temp directory
$appdataLocalLowTempPath = "$env:userprofile\Appdata\LocalLow\Temp"

if (Test-Path -Path "$appdataLocalLowTempPath") {
    Write-Host "Removing temp files #3" -ForegroundColor Green
    # Get all files in the Temp directory and its subdirectories
    # Filter files older than 3 days and delete them
    Get-ChildItem -Path $appdataLocalLowTempPath -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Output "All files older than 3 days in $appdataLocalLowTempPath have been processed."
}

# Define the path to the Temp directory
$programdataTempPath = "$env:ProgramData\Microsoft\Search\Data\Temp"

if (Test-Path -Path "$programdataTempPath") {
    Write-Host "Removing temp files #4" -ForegroundColor Green
    # Get all files in the Temp directory and its subdirectories
    # Filter files older than 3 days and delete them
    Get-ChildItem -Path $programdataTempPath -Recurse -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    # Optional: Output a message to confirm the deletion
    Write-Output "All files older than 3 days in $programdataTempPath have been processed."
}

# Remove .rbs files
# RBS files are created for use in Windows telemetry
# Define the paths to process
$rbsPaths = @("$env:ProgramData\Microsoft\Diagnosis")

foreach ($path in $rbsPaths) {
    if (Test-Path -Path "$path") {
        Write-Host "Removing .rbs files from $path" -ForegroundColor Green
        # Get all .rbs files recursively and delete them
        Get-ChildItem -Path $path -Recurse -Filter *.rbs -ErrorAction SilentlyContinue -ErrorVariable myErrors | ForEach-Object {
            try {
                Write-Output "Processing: $($_.FullName)"
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch [System.UnauthorizedAccessException] {
                # Handles specific UnauthorizedAccessException
                Write-Output "UnauthorizedAccessException for: $($_.FullName)"
            } catch {
                # Handles other exceptions
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                try {
                    # Take ownership of the file
                    Take-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                    Remove-Item -Path $($_.TargetObject) -Force -ErrorAction Stop
                    Write-Host "Deleted: $($_.TargetObject)" -ForegroundColor Yellow
                } catch {
                    # Handles other exceptions
                    Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                } finally {
                    # Restore the original ownership and ACLs if file still exists
                    if ($originalAcl -ne $null -and $originalOwner -ne $null) {
                        if (Test-Path "$($_.TargetObject)" -PathType Leaf) {
                            Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                        }
                    } else {
                        Write-Warning "Original ACL and owner information is missing, cannot restore."
                    }
                }
            }
        }

        # Check for and report any errors captured in the ErrorVariable
        if ($myErrors) {
            Write-Host "Errors encountered:" -ForegroundColor Yellow
            $myErrors | ForEach-Object {
                Write-Host "Error for: $($_.TargetObject)" -ForegroundColor Red
                if (Test-Path -Path "$($_.TargetObject)" -PathType Container) {
                    try {
                        # Take ownership of the folder
                        Take-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner

                        # Get all .rbs files recursively and delete them
                        Get-ChildItem -Path "$($_.TargetObject)" -Recurse -Filter *.rbs -ErrorAction SilentlyContinue -ErrorVariable myErrors | ForEach-Object {
                            try {
                                Write-Output "Processing: $($_.FullName)"
                                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
                            } catch [System.UnauthorizedAccessException] {
                                # Handles specific UnauthorizedAccessException
                                Write-Output "UnauthorizedAccessException for: $($_.FullName)"
                            } catch {
                                # Handles other exceptions
                                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
                            }
                        }
                    } catch {
                        Write-Error "An error occurred during the operation: $_"
                    } finally {
                        # Restore the original ownership and ACLs
                        if ($originalAcl -ne $null -and $originalOwner -ne $null) {
                            Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                        } else {
                            Write-Warning "Original ACL and owner information is missing, cannot restore."
                        }
                    }
                }
            }
        }
        Write-Output "All .rbs files in the specified paths have been processed."
    } else {
        Write-Output "Path does not exist: $path"
    }
}

# https://blog.expta.com/2008/10/fix-for-large-frameworklog-files.html
$wbemLogsPath = "$Env:WinDir\System32\wbem\Logs"

if (Test-Path -Path "$wbemLogsPath") {
    Write-Host "Removing wbem log files" -ForegroundColor Green
    # Get all .log and .txt files in the Temp directory and its subdirectories
    Get-ChildItem -Path $wbemLogsPath -Recurse -File | Where-Object {
        $_.Extension -eq ".log" -or $_.Extension -eq ".txt" -or $_.Extension -eq ".lo_"
    } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Output "All .log and .txt files in $wbemLogsPath have been processed."
}

$catroot2LogsPath = "$Env:WinDir\System32\catroot2"

if (Test-Path -Path "$catroot2LogsPath") {
    Write-Host "Removing catroot2 log files" -ForegroundColor Green

    Write-Output "Stopping the cryptsvc service..."
    Stop-Service -Name "cryptsvc" -Force -ErrorAction SilentlyContinue

    # Get all .log and .txt files in the Temp directory and its subdirectories
    Get-ChildItem -Path $catroot2LogsPath -Recurse -File | Where-Object {
        $_.Extension -eq ".log" -or $_.Extension -eq ".txt"
    } | ForEach-Object {
        try {
            Remove-Item -Path $_.FullName -Force -ErrorAction Stop
            Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
        } catch {
            Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
        }
    }
    Write-Output "Starting the cryptsvc service..."
    Start-Service -Name "cryptsvc" -ErrorAction SilentlyContinue

    Write-Output "All .log and .txt files in $catroot2LogsPath have been processed."
}

#$reportArchivePath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive"

#if (Test-Path -Path $reportArchivePath) {
    #Remove-Item -Path $reportArchivePath -Recurse -Force
    #Write-Output "Deleted: $reportArchivePath"
#} else {
    #Write-Output "Path does not exist: $reportArchivePath"
#}

# Delete queued and archived Windows Error Reporting (WER) reports
$reportArchivePath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive"

if (Test-Path -Path $reportArchivePath) {
    Write-Host "Delete queued and archived Windows Error Reporting (WER) reports" -ForegroundColor Green
    Get-ChildItem -Path $reportArchivePath -Recurse | Remove-Item -Recurse -Force
    Write-Host "Contents of $reportArchivePath have been deleted." -ForegroundColor Yellow
} else {
    Write-Output "Path does not exist: $reportArchivePath"
}

$reportQueuePath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportQueue"

if (Test-Path -Path $reportQueuePath) {
    Write-Host "Delete queued and archived Windows Error Reporting (WER) reports" -ForegroundColor Green
    Get-ChildItem -Path $reportQueuePath -Recurse | Remove-Item -Recurse -Force
    Write-Host "Contents of $reportQueuePath have been deleted." -ForegroundColor Yellow
} else {
    Write-Output "Path does not exist: $reportQueuePath"
}

# Delete dmp files
$dmpPaths = @("$Env:WinDir\LiveKernelReports", "$env:userprofile\Appdata\Local\CrashDumps", "$Env:WinDir\Minidump")
foreach ($path in $dmpPaths) {
    if (Test-Path -Path "$path") {
        Write-Host "Removing .dmp files" -ForegroundColor Green
        # Get all .dmp files in the directory and its subdirectories
        Get-ChildItem -Path $path -Recurse -File | Where-Object {
            $_.Extension -eq ".dmp"
        } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }
        Write-Output "All .dmp files in $path have been processed."
    }
}

if (Test-Path -Path "$Env:WinDir\MEMORY.dmp") {
    Remove-Item -Path "$Env:WinDir\MEMORY.dmp" -Force
}

# CHECK INTEGRITY AND DEFRAG DATABASES
if (Test-Path -Path "$Env:WinDir\SoftwareDistribution\DataStore\DataStore.edb") {
    Write-Host "Check integrity and defrag datastore.edb" -ForegroundColor Green

    # Stop the wuauserv and bits services
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name bits -Force -ErrorAction SilentlyContinue

    # Check integrity of the DataStore.edb file
    # Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/g $Env:WinDir\SoftwareDistribution\DataStore\DataStore.edb" -Wait

    # Defragment the DataStore.edb file
    Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/d $Env:WinDir\SoftwareDistribution\DataStore\DataStore.edb" -Wait

    # Start the bits and wuauserv services
    Start-Service -Name bits
    Start-Service -Name wuauserv
}

if (Test-Path -Path "$env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb") {
    Write-Host "Check integrity and defrag windows.edb" -ForegroundColor Green

    # Stop the wsearch services
    Stop-Service -Name wsearch -Force -ErrorAction SilentlyContinue

    # Check integrity of the Windows.edb file
    # Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/g $env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Wait

    # Defragment the Windows.edb file
    Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/d $env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Wait

    # Start the wsearch service
    Start-Service -Name wsearch
}

# Delete duplicate files in users download folder
# Define source directory
$srcDir = "$env:USERPROFILE\Downloads"

# Function to find and list duplicate files
function Find-DuplicateFiles {
    param (
        [string]$DirectoryPath
    )

    # Ensure the directory exists
    if (-Not (Test-Path -Path $DirectoryPath)) {
        Write-Error "Directory does not exist: $DirectoryPath"
        return
    }

    # Array to store duplicate files with their originals
    $duplicateFiles = @()

    # Get all files, group by Length (size), filter those with more than one occurrence
    $filesByLength = Get-ChildItem -Path $DirectoryPath -File -Recurse | 
        Group-Object -Property Length | 
        Where-Object { $_.Count -gt 1 }

    foreach ($group in $filesByLength) {
        # Get file hash and original file object
        $filesWithHash = $group.Group | ForEach-Object {
            [PSCustomObject]@{
                FileInfo = $_
                Hash = (Get-FileHash -Path $_.FullName).Hash
            }
        }

        # Group by hash and process duplicates
        $filesByHash = $filesWithHash | Group-Object -Property Hash | Where-Object { $_.Count -gt 1 }
        foreach ($hashGroup in $filesByHash) {
            $files = $hashGroup.Group | Sort-Object -Property { $_.FileInfo.CreationTime }
            $originalFile = $files[0].FileInfo
            $files | Select-Object -Skip 1 | ForEach-Object {
                $duplicateFiles += [PSCustomObject]@{
                    OriginalFilePath         = $originalFile.FullName
                    OriginalFileCreationTime = $originalFile.CreationTime
                    OriginalFileSize         = $originalFile.Length
                    DuplicateFilePath       = $_.FileInfo.FullName
                    DuplicateFileCreationTime = $_.FileInfo.CreationTime
                    DuplicateFileSize       = $_.FileInfo.Length
                }
            }
        }
    }

    return $duplicateFiles
}

# Call the function to find duplicate files
$duplicates = Find-DuplicateFiles -DirectoryPath $srcDir

if ($duplicates) {
    Write-Host "Deleting duplicates in Downloads folder" -ForegroundColor Green
    
    # Display the duplicate files in a grid view for the user to select
    $selectedFiles = $duplicates | Out-GridView -Title "Select files to delete" -PassThru

    if ($selectedFiles) {
        # Confirm deletion
        $confirmDeletion = Read-Host "Are you sure you want to delete the selected files? (y/n)"
        if ($confirmDeletion -eq 'y') {
            $selectedFiles | ForEach-Object {
                try {
                    Remove-Item -Path $_.DuplicateFilePath -Force -ErrorAction Stop
                    Write-Host "Deleted: $($_.DuplicateFilePath)" -ForegroundColor Yellow
                } catch {
                    Write-Host "Failed to delete $($_.DuplicateFilePath): $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Output "Deletion cancelled by user."
        }
    } else {
        Write-Output "No files selected for deletion."
    }
} else {
    Write-Output "No duplicate files found."
}


# https://www.tenforums.com/performance-maintenance/149630-old-devices-driver-cleanup-one-command.html
#For pnpclean output see c:\windows\inf\setupapi.dev.log

#PNPCLEAN [/DEVICES] [/DRIVERS] [/FILES] [/MAXCLEAN] [/NOREMOVE] /? /help /h

#/DEVICES Removes devices missing for the default time period
#/DRIVERS Removes redundant drivers from the system
#/FILES Removes files/directories that are no longer needed that are related to devices and drivers.
#/MAXCLEAN Performs maximum cleanup
#For /DEVICES this will set the time period to 0 so that every missing device will be processed for removal. (Note: Default missing device timeout period is 30 days!!!)
#For /DRIVERS this will allow every driver that is not installed on some device to be processed for removal.
#For /FILES this currently has no effect on what is removed.
#/NOREMOVE Evaluate items only, do not remove
try {
    Write-Host "Cleanup old drivers" -ForegroundColor Green
    Start-Process -FilePath "$Env:WinDir\System32\Rundll32.exe" -ArgumentList "$Env:WinDir\System32\pnpclean.dll,RunDLL_PnpClean /DEVICES /DRIVERS /FILES" -Wait
} catch {
    Write-Error "An error occurred: $_"
}

# Define the path to cleanmgr.exe
$cleanMgrPath = "$env:SystemRoot\SYSTEM32\cleanmgr.exe"

# Check if cleanmgr.exe exists
if (Test-Path -Path $cleanMgrPath) {
    Write-Host "Running windows cleanmanager" -ForegroundColor Green
    # Run cleanmgr with the specified arguments
    Start-Process -FilePath $cleanMgrPath -ArgumentList "/sagerun:112" -Wait
} else {
    Write-Output "cleanmgr.exe does not exist at $cleanMgrPath"
}

Write-Host "Clear RecycleBin" -ForegroundColor Green
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Capture free space after cleaning
$finalFreeSpaceBytes = Get-FreeSpace -driveRoot $windowsDriveRoot
$finalFreeSpaceGB = [math]::round($finalFreeSpaceBytes / 1GB, 2)
$finalFreeSpaceMB = [math]::round($finalFreeSpaceBytes / 1MB, 2)

Write-Host "Final Free Space: $finalFreeSpaceGB GB ($finalFreeSpaceMB MB) ($finalFreeSpaceBytes Bytes)" -ForegroundColor Green

# Calculate reclaimed space
$reclaimedSpaceBytes = $finalFreeSpaceBytes - $initialFreeSpaceBytes
$reclaimedSpaceGB = [math]::round($reclaimedSpaceBytes / 1GB, 2)
$reclaimedSpaceMB = [math]::round($reclaimedSpaceBytes / 1MB, 2)

Write-Host "Reclaimed Space: $reclaimedSpaceGB GB ($reclaimedSpaceMB MB) ($reclaimedSpaceBytes Bytes)" -ForegroundColor Green

Write-Host "Press any key to exit..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit
