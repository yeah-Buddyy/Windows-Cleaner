# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# Rename title window
$host.ui.RawUI.WindowTitle = "Windows Cleaner"

# Increase the buffer size
$bufferHeight = 9999
$console = [System.Console]::BufferHeight = $bufferHeight
Write-Output "Buffer size increased to Height: $bufferHeight"

# Enable LongPaths
$global:currentlongPathsEnabledValue = ""
$longPathsEnabledRegKey = "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\FileSystem"
if (-not (Test-Path -Path $longPathsEnabledRegKey)) {
    New-Item -Path $longPathsEnabledRegKey -Force
}
if ((Get-Item -Path $longPathsEnabledRegKey).GetValue("LongPathsEnabled") -ne $null) {
    if ((Get-Item -Path $longPathsEnabledRegKey).GetValue("LongPathsEnabled") -eq "0") {
        $global:currentlongPathsEnabledValue = "0"
        New-ItemProperty -Path $longPathsEnabledRegKey -Force -Name "LongPathsEnabled" -PropertyType "Dword" -Value "1"
        Write-Output "Temporary enabled LongPaths"
    }
} else {
    $global:currentlongPathsEnabledValue = "0"
    #Get-ItemPropertyValue "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\FileSystem" "LongPathsEnabled"
    New-ItemProperty -Path $longPathsEnabledRegKey -Force -Name "LongPathsEnabled" -PropertyType "Dword" -Value "1"
    Write-Output "Temporary enabled LongPaths"
}

$LogDate = Get-Date -Format "MM-d-yy-HHmm"
# Define log file location
$Cleanuplog = "$PSScriptRoot\Windows-Cleaner_$LogDate.log"

# Create backup folder
$aclBackupPath = "$PSScriptRoot\ACL-Backup"
if (-not (Test-Path -Path $aclBackupPath)) {
    New-Item -ItemType Directory -Path $aclBackupPath -Force | Out-Null
    Write-Output "Created backup folder $aclBackupPath"
}

function Save-Acl {
    param (
        [parameter(Mandatory = $true)][string]$Path,
        [parameter(Mandatory = $true)][string]$OutputFile
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            Write-Error "The specified path does not exist: $Path"
            return
        }

        # Get the ACL of the specified path
        $acl = Get-Acl -Path $Path

        # Export the ACL to an XML file
        $acl | Export-Clixml -Path $OutputFile -ErrorAction Stop

        Write-Output "ACL for '$Path' has been successfully saved to '$OutputFile'."
    } catch {
        Write-Error "Failed to save ACL: $_"
    }
}

function Restore-Acl {
    param (
        [parameter(Mandatory = $true)][string]$Path,
        [parameter(Mandatory = $true)][string]$InputFile
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            Write-Error "The specified path does not exist: $Path"
            return
        }

        if (-not (Test-Path -Path $InputFile)) {
            Write-Error "The specified input file does not exist: $InputFile"
            return
        }

        # Import the ACL from the XML file
        $acl = Import-Clixml -Path $InputFile -ErrorAction Stop

        # Set the ACL to the specified path
        Set-Acl -Path $Path -AclObject $acl

        Write-Output "ACL for '$Path' has been successfully restored from '$InputFile'."
    } catch {
        Write-Error "Failed to restore ACL: $_"
    }
}
# Restore the ACL
# Restore-Acl -Path "C:\Path\To\FileOrFolder" -InputFile "C:\Path\To\Save\Acl.xml"

function Transform-ToValidName {
    param (
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    # Get the invalid characters for file and folder names
    $invalidChars = [IO.Path]::GetInvalidFileNameChars()

    # Replace invalid characters with an underscore
    $validName = $Path -replace "[$([RegEx]::Escape([string]::Join('', $invalidChars)))]", "_"

    return $validName
}

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
        if (Test-Path $Path -PathType Container) {
            $validFolderName = Transform-ToValidName -Path $Path
            if (-not (Test-Path -Path "$aclBackupPath\$validFolderName")) {
                # Save the ACL
                Save-Acl -Path $Path -OutputFile "$aclBackupPath\$validFolderName.xml"
            }
        } else {
            $validFileName = Transform-ToValidName -Path $Path
            if (-not (Test-Path -Path "$aclBackupPath\$validFileName" -PathType Leaf)) {
                # Save the ACL
                Save-Acl -Path $Path -OutputFile "$aclBackupPath\$validFileName.xml"
            }
        }

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

function Get-TrimStatus {
    # Run the fsutil command and capture the output
    $output = fsutil behavior query disabledeletenotify

    # Initialize flags to track TRIM status for NTFS and ReFS
    $ntfsTrimEnabled = $false
    $refsTrimEnabled = $false

    # Check the output lines for the status of DisableDeleteNotify
    $output -split "`n" | ForEach-Object {
        if ($_ -match "NTFS DisableDeleteNotify = (\d)") {
            $ntfsStatus = [int]$matches[1]
            $ntfsTrimEnabled = $ntfsStatus -eq 0
        }
        if ($_ -match "ReFS DisableDeleteNotify = (\d)") {
            $refsStatus = [int]$matches[1]
            $refsTrimEnabled = $refsStatus -eq 0
        }
    }

    # Output the results
    if ($ntfsTrimEnabled) {
        Write-Output "TRIM is enabled for NTFS."
    } else {
        Write-Output "TRIM is disabled for NTFS."
    }

    if ($refsTrimEnabled) {
        Write-Output "TRIM is enabled for ReFS."
    } else {
        Write-Output "TRIM is disabled for ReFS."
    }

    if (-not $ntfsTrimEnabled -and -not $refsTrimEnabled) {
        Write-Output "TRIM is disabled on all file systems."
        return $false
    } elseif (-not $ntfsTrimEnabled -or -not $refsTrimEnabled) {
        Write-Output "TRIM is disabled on ntfs or refs file system."
        return $false
    }
    return $true
}

# Function to get the free space on the Windows drive
function Get-FreeSpace {
    param (
        [string]$driveRoot
    )
    $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -eq $driveRoot }
    return $drive.Free
}

# Calculate size of a folder
function Get-FolderSize {
    param (
        [string]$folderPath
    )
    if (Test-Path -Path $folderPath) {
        return (Get-ChildItem -Path $folderPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    } else {
        return 0
    }
}

function GetMachineType {
    $computerSystemInfo = Get-CimInstance -Class Win32_ComputerSystem
    $model = $computerSystemInfo.Model.ToLower()
    $manufacturer = $computerSystemInfo.Manufacturer.ToLower()

    switch ($model) {
        "vmware virtual platform" {
            Write-Output "This Machine is Virtual on VMware Virtual Platform."
            return $true
        }
        "virtualbox" {
            Write-Output "This Machine is Virtual on Oracle VM Platform."
            return $true
        }
        "virtual machine" {
            Write-Output "This Machine is Virtual on Hyper-V Platform."
            return $true
        }
        "virtual" {
            Write-Output "This Machine is Virtual on Parallels Platform."
            return $true
        }
    }

    switch ($manufacturer) {
        "xen" {
            Write-Output "This Machine is Virtual on Xen Platform."
            return $true
        }
        "qemu" {
            Write-Output "This Machine is Virtual on KVM Platform."
            return $true
        }
        "microsoft corporation" {
            if (Get-Service -Name "WindowsAzureGuestAgent" -ErrorAction SilentlyContinue) {
                Write-Output "This Machine is Virtual on Azure Platform."
            } else {
                Write-Output "This Machine is Virtual on Hyper-V Platform."
            }
            return $true
        }
        "google" {
            Write-Output "This Machine is Virtual on Google Cloud."
            return $true
        }
        default {
            $uuid = (Get-CimInstance -Query "SELECT UUID FROM Win32_ComputerSystemProduct").UUID
            if ($uuid.Substring(0, 3).toLower() -match "ec2") {
                Write-Output "This Machine is Virtual on AWS."
                return $true
            } else {
                # Write-Output "This Machine is Physical Platform."
                return $false
            }
        }
    }
    return $false
}

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
                    Write-Host "Removed 'StateFlags0112' from $keyPath" -ForegroundColor Yellow
                }
            }
        }
    }

    # Start recursion
    Recurse-RemoveStateFlags0112 -keyPath $regPath
}

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

# Clear the print queue
function ClearPrintQueue {
    try {
        # Stop the Print Spooler service
        Write-Output "Stopping the Print Spooler service..."
        Stop-Service -Name "spooler" -Force -ErrorAction Stop

        # Define the path to the print queue directory
        $printerPath = "$env:SystemRoot\System32\spool\PRINTERS"

        # Delete the print queue files
        Write-Output "Deleting print queue files..."
        Remove-Item -Path "$printerPath\*.*" -Force -ErrorAction Stop

        # Start the Print Spooler service
        Write-Output "Starting the Print Spooler service..."
        Start-Service -Name "spooler" -ErrorAction Stop

        Write-Output "Print queue cleared successfully."
    } catch {
        Write-Error "An error occurred: $_"
    }
}

# Function to clear the SoftwareDistribution Download folder
# Only recommended if there are no pending Windows updates. We will take care of this ;)
function Clear-SoftwareDistributionDownloadFolder {
    param (
        [string]$FolderPath
    )

    try {
        # Stop the BITS service and the Windows Update service
        Write-Output "Stopping BITS and Windows Update services..."
        Stop-Service -Name "bits" -Force -ErrorAction Stop
        Stop-Service -Name "wuauserv" -Force -ErrorAction Stop

        # Clear the contents of the Download folder
        Write-Output "Clearing contents of $FolderPath..."
        Get-ChildItem -Path $FolderPath -Recurse | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }

        # Start the BITS service and the Windows Update service
        Write-Output "Starting BITS and Windows Update services..."
        Start-Service -Name "bits"
        Start-Service -Name "wuauserv"

        Write-Output "Cleared all folders and files from $FolderPath successfully."
    } catch {
        Write-Error "An error occurred while clearing $FolderPath $_"
    }
}

function Get-PendingWindowsUpdates {
    # Create an update session
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    
    # Create an update searcher
    $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
    
    # Search for updates that are not hidden and not installed
    $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
    
    if ($Updates.Count -gt 0) {
        Write-Output "Pending/Missing Windows Updates:"
        $Updates | Select-Object Title, Description
        return $true
    } else {
        Write-Output "No pending or missing Windows updates found."
        return $false
    }
}

function DeleteEtlFiles {
    # Removing .etl files
    # https://www.partitionwizard.com/partitionmanager/free-up-ssd-space-consumed-with-etl-files.html
    # ETL files are log files that contain event logs generated by Microsoft Operating System Kernel. These log files include application and system-level errors, warnings, and other events data
    # Define the paths to process
    $etlPaths = @("$env:WINDIR", "$env:userprofile\Appdata\Local\Diagnostics", "$env:userprofile\Appdata\Local\Microsoft", "$env:userprofile\Appdata\Roaming\Microsoft", "$env:ProgramData\USOShared", "$env:ProgramData\PLUG", "$env:ProgramData\Microsoft")
    foreach ($path in $etlPaths) {
        if (Test-Path -Path "$path") {
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
                        if ($originalAcl.Value -ne $null -and $originalOwner.Value -ne $null) {
                            if (Test-Path "$($_.TargetObject)" -PathType Leaf) {
                                Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                            }
                        } else {
                            Write-Warning "Original ACL and owner information is missing, cannot restore."
                        }
                        # Reset the [ref] variables after each iteration
                        $originalAcl.Value = $null
                        $originalOwner.Value = $null
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
                            if ($originalAcl.Value -ne $null -and $originalOwner.Value -ne $null) {
                                Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                            } else {
                                Write-Warning "Original ACL and owner information is missing, cannot restore."
                            }
                            # Reset the [ref] variables after each iteration
                            $originalAcl.Value = $null
                            $originalOwner.Value = $null
                        }
                    }
                }
            }
            Write-Output "All .etl files in the specified paths have been processed."
        } else {
            Write-Output "Path does not exist: $path"
        }
    }
}

function DeleteTempFiles {
    # Define the path to the Temp directory
    # Get-ChildItem -Force parameter includes hidden files
    $tempPath = "$env:TEMP"

    if (Test-Path -Path "$tempPath") {
        Write-Output "Removing temp files from $tempPath"
        # Get all files in the Temp directory and its subdirectories
        # Filter files older than 5 days and delete them
        Get-ChildItem -Path $tempPath -Recurse -Force -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }
        Write-Output "All files older than 5 days in $tempPath have been processed."
    }
    if (Test-Path -Path "$tempPath") {
        # Get all directories in the Temp directory and its subdirectories
        $dirs = Get-ChildItem -Path $tempPath -Recurse -Force -Directory | Sort-Object -Property FullName -Descending
        foreach ($dir in $dirs) {
            # Check if the directory is empty
            if (!(Get-ChildItem -Path $dir.FullName -Force)) {
                try {
                    Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                    Write-Host "Deleted empty directory: $($dir.FullName)" -ForegroundColor Yellow
                } catch {
                    Write-Host "Failed to delete directory $($dir.FullName): $_" -ForegroundColor Red
                }
            }
        }
        Write-Output "All empty directories in $tempPath have been processed."
    }

    # Define the path to the Temp directory
    $windirTempPath = "$Env:WinDir\Temp"

    if (Test-Path -Path "$windirTempPath") {
        Write-Output "Removing temp files from $windirTempPath"
        # Get all files in the Temp directory and its subdirectories
        # Filter files older than 5 days and delete them
        Get-ChildItem -Path $windirTempPath -Recurse -Force -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }
        Write-Output "All files older than 5 days in $windirTempPath have been processed."
    }
    if (Test-Path -Path "$windirTempPath") {
        # Get all directories in the Temp directory and its subdirectories
        $dirs = Get-ChildItem -Path $windirTempPath -Recurse -Force -Directory | Sort-Object -Property FullName -Descending
        foreach ($dir in $dirs) {
            # Check if the directory is empty
            if (!(Get-ChildItem -Path $dir.FullName -Force)) {
                try {
                    Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                    Write-Host "Deleted empty directory: $($dir.FullName)" -ForegroundColor Yellow
                } catch {
                    Write-Host "Failed to delete directory $($dir.FullName): $_" -ForegroundColor Red
                }
            }
        }
        Write-Output "All empty directories in $windirTempPath have been processed."
    }

    # Define the path to the Temp directory
    $appdataLocalLowTempPath = "$env:userprofile\Appdata\LocalLow\Temp"

    if (Test-Path -Path "$appdataLocalLowTempPath") {
        Write-Output "Removing temp files from $appdataLocalLowTempPath"
        # Get all files in the Temp directory and its subdirectories
        # Filter files older than 5 days and delete them
        Get-ChildItem -Path $appdataLocalLowTempPath -Recurse -Force -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }
        Write-Output "All files older than 5 days in $appdataLocalLowTempPath have been processed."
    }
    if (Test-Path -Path "$appdataLocalLowTempPath") {
        # Get all directories in the Temp directory and its subdirectories
        $dirs = Get-ChildItem -Path $appdataLocalLowTempPath -Recurse -Force -Directory | Sort-Object -Property FullName -Descending
        foreach ($dir in $dirs) {
            # Check if the directory is empty
            if (!(Get-ChildItem -Path $dir.FullName -Force)) {
                try {
                    Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                    Write-Host "Deleted empty directory: $($dir.FullName)" -ForegroundColor Yellow
                } catch {
                    Write-Host "Failed to delete directory $($dir.FullName): $_" -ForegroundColor Red
                }
            }
        }
        Write-Output "All empty directories in $appdataLocalLowTempPath have been processed."
    }

    # Define the path to the Temp directory
    $programdataTempPath = "$env:ProgramData\Microsoft\Search\Data\Temp"

    if (Test-Path -Path "$programdataTempPath") {
        Write-Output "Removing temp files from $programdataTempPath"
        # Get all files in the Temp directory and its subdirectories
        # Filter files older than 5 days and delete them
        Get-ChildItem -Path $programdataTempPath -Recurse -Force -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-5) } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }
        # Optional: Output a message to confirm the deletion
        Write-Output "All files older than 5 days in $programdataTempPath have been processed."
    }
    if (Test-Path -Path "$programdataTempPath") {
        # Get all directories in the Temp directory and its subdirectories
        $dirs = Get-ChildItem -Path $programdataTempPath -Recurse -Force -Directory | Sort-Object -Property FullName -Descending
        foreach ($dir in $dirs) {
            # Check if the directory is empty
            if (!(Get-ChildItem -Path $dir.FullName -Force)) {
                try {
                    Remove-Item -Path $dir.FullName -Recurse -Force -ErrorAction Stop
                    Write-Host "Deleted empty directory: $($dir.FullName)" -ForegroundColor Yellow
                } catch {
                    Write-Host "Failed to delete directory $($dir.FullName): $_" -ForegroundColor Red
                }
            }
        }
        Write-Output "All empty directories in $programdataTempPath have been processed."
    }
}

function DeleteRbsFiles {
    # Remove .rbs files
    # RBS files are created for use in Windows telemetry
    # Define the paths to process
    $rbsPaths = @("$env:ProgramData\Microsoft\Diagnosis")

    foreach ($path in $rbsPaths) {
        if (Test-Path -Path "$path") {
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
                        if ($originalAcl.Value -ne $null -and $originalOwner.Value -ne $null) {
                            if (Test-Path "$($_.TargetObject)" -PathType Leaf) {
                                Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                            }
                        } else {
                            Write-Warning "Original ACL and owner information is missing, cannot restore."
                        }
                        # Reset the [ref] variables after each iteration
                        $originalAcl.Value = $null
                        $originalOwner.Value = $null
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
                            if ($originalAcl.Value -ne $null -and $originalOwner.Value -ne $null) {
                                Restore-Ownership -Path "$($_.TargetObject)" -OriginalAcl $originalAcl -OriginalOwner $originalOwner
                            } else {
                                Write-Warning "Original ACL and owner information is missing, cannot restore."
                            }
                            # Reset the [ref] variables after each iteration
                            $originalAcl.Value = $null
                            $originalOwner.Value = $null
                        }
                    }
                }
            }
            Write-Output "All .rbs files in the specified paths have been processed."
        } else {
            Write-Output "Path does not exist: $path"
        }
    }
}

function DeleteLogFiles {
    # https://blog.expta.com/2008/10/fix-for-large-frameworklog-files.html
    $wbemLogsPath = "$Env:WinDir\System32\wbem\Logs"

    if (Test-Path -Path "$wbemLogsPath") {
        Write-Output "Removing log files from $wbemLogsPath"
        # Get all .log and .txt files in the directory and its subdirectories
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
        Write-Output "Removing log files from $catroot2LogsPath"

        Write-Output "Stopping the cryptsvc service..."
        Stop-Service -Name "cryptsvc" -Force -ErrorAction SilentlyContinue

        # Get all .log and .txt files in the directory and its subdirectories
        Get-ChildItem -Path $catroot2LogsPath -Recurse -File | Where-Object {
            $_.Extension -eq ".log" -or $_.Extension -eq ".txt" -or $_.Extension -eq ".lo_"
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

    # https://blog.idera.com/database-tools/cleaning-week-finding-fat-log-file-backups/
    $windowsLogsPath = "$Env:WinDir\Logs"

    if (Test-Path -Path "$windowsLogsPath") {
        Write-Output "Removing log files from $windowsLogsPath"

        # Needed to remove logs from the cbs folder
        # https://blog.idera.com/database-tools/cleaning-week-deleting-cbs-log-file/
        Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

        # Get all .log and .etl files in the directory and its subdirectories
        Get-ChildItem -Path $windowsLogsPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -eq ".log" -or $_.Extension -eq ".etl" -or $_.Extension -eq ".lo_" -or $_.Extension -eq ".cab"
        } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }

        Write-Output "All .log, .etl and .cab files in $windowsLogsPath have been processed."

        Start-Service -Name TrustedInstaller
    }

    $windowsLogFilesPath = "$Env:WinDir\System32\LogFiles"

    if (Test-Path -Path "$windowsLogFilesPath") {
        Write-Output "Removing log files from $windowsLogFilesPath"

        # Get all .log and .etl files in the directory and its subdirectories
        Get-ChildItem -Path $windowsLogFilesPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -eq ".log" -or $_.Extension -eq ".etl" -or $_.Extension -eq ".lo_"
        } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }

        Write-Output "All .log and .etl files in $windowsLogFilesPath have been processed."
    }

    $netFrameworkLogFilesPath = "$Env:WinDir\Microsoft.NET"

    if (Test-Path -Path "$netFrameworkLogFilesPath") {
        Write-Output "Removing log files from $netFrameworkLogFilesPath"

        # Get all .log files in the directory and its subdirectories
        Get-ChildItem -Path $netFrameworkLogFilesPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Extension -eq ".log" -or $_.Extension -eq ".lo_"
        } | ForEach-Object {
            try {
                Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                Write-Host "Deleted: $($_.FullName)" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to delete $($_.FullName): $_" -ForegroundColor Red
            }
        }

        Write-Output "All .log and .etl files in $netFrameworkLogFilesPath have been processed."
    }
}

function CleanWindowsErrorReporting {
    # Delete queued and archived Windows Error Reporting (WER) reports
    $reportArchivePath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive"

    if (Test-Path -Path $reportArchivePath) {
        Write-Output "Delete queued and archived Windows Error Reporting (WER) reports"
        Get-ChildItem -Path $reportArchivePath -Recurse | Remove-Item -Recurse -Force
        Write-Host "Contents of $reportArchivePath have been deleted." -ForegroundColor Yellow
    } else {
        Write-Output "Path does not exist: $reportArchivePath"
    }

    $reportQueuePath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportQueue"

    if (Test-Path -Path $reportQueuePath) {
        Write-Output "Delete queued and archived Windows Error Reporting (WER) reports"
        Get-ChildItem -Path $reportQueuePath -Recurse | Remove-Item -Recurse -Force
        Write-Host "Contents of $reportQueuePath have been deleted." -ForegroundColor Yellow
    } else {
        Write-Output "Path does not exist: $reportQueuePath"
    }

    $werTempPath = "$env:ALLUSERSPROFILE\Microsoft\Windows\WER\Temp"

    if (Test-Path -Path $werTempPath) {
        Write-Output "Delete queued and archived Windows Error Reporting (WER) reports"
        Get-ChildItem -Path $werTempPath -Recurse | Remove-Item -Recurse -Force
        Write-Host "Contents of $werTempPath have been deleted." -ForegroundColor Yellow
    } else {
        Write-Output "Path does not exist: $werTempPath"
    }
}

function DeleteDmpFiles {
    # Delete dmp files
    $dmpPaths = @("$Env:WinDir\LiveKernelReports", "$env:userprofile\Appdata\Local\CrashDumps", "$Env:WinDir\Minidump")
    foreach ($path in $dmpPaths) {
        if (Test-Path -Path "$path") {
            Write-Output "Removing .dmp files from $path"
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
}

function DefragDatabases {
    # CHECK INTEGRITY AND DEFRAG DATABASES
    if (Test-Path -Path "$Env:WinDir\SoftwareDistribution\DataStore\DataStore.edb") {
        Write-Output "Check integrity and defrag datastore.edb"

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
        Write-Output "Check integrity and defrag windows.edb"

        # Stop the wsearch services
        Stop-Service -Name wsearch -Force -ErrorAction SilentlyContinue

        # Check integrity of the Windows.edb file
        # Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/g $env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Wait

        # Defragment the Windows.edb file
        Start-Process -FilePath "$Env:WinDir\System32\esentutl.exe" -ArgumentList "/d $env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" -Wait

        # Start the wsearch service
        Start-Service -Name wsearch
    }
}

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
            $originalHash = $files[0].Hash
            $files | Select-Object -Skip 1 | ForEach-Object {
                $duplicateFiles += [PSCustomObject]@{
                    OriginalFilePath            = $originalFile.FullName
                    OriginalFileCreationTime    = $originalFile.CreationTime
                    OriginalFileSize            = $originalFile.Length
                    OriginalFileHash            = $originalHash
                    DuplicateFilePath           = $_.FileInfo.FullName
                    DuplicateFileCreationTime   = $_.FileInfo.CreationTime
                    DuplicateFileSize           = $_.FileInfo.Length
                    DuplicateFileHash           = $_.Hash
                }
            }
        }
    }

    return $duplicateFiles
}

function CleanOldDriversAndDevices {
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
        Start-Process -FilePath "$Env:WinDir\System32\Rundll32.exe" -ArgumentList "$Env:WinDir\System32\pnpclean.dll,RunDLL_PnpClean /DEVICES /DRIVERS /FILES" -Wait
    } catch {
        Write-Error "An error occurred: $_"
    }
}

function CleanManager {
    # Define the path to cleanmgr.exe
    $cleanMgrPath = "$env:SystemRoot\SYSTEM32\cleanmgr.exe"

    # Check if cleanmgr.exe exists
    if (Test-Path -Path $cleanMgrPath) {
        # Run cleanmgr with the specified arguments
        Start-Process -FilePath $cleanMgrPath -ArgumentList "/sagerun:112" -Wait
    } else {
        Write-Output "cleanmgr.exe does not exist at $cleanMgrPath"
    }
}

function StartComponentCleanup {
    # Cleans the Component Store of any broken hard links It's imperative folks on Insider Builds run this regularly due to the frequent updates
    # Run the DISM command
    $processStartComponentCleanup = Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /NoRestart /Cleanup-Image /StartComponentCleanup" -Verb RunAs -PassThru

    # Wait for the process to exit
    $processStartComponentCleanup | Wait-Process

    # Get the exit code
    $exitCodeStartComponentCleanup = $processStartComponentCleanup.ExitCode

    # Check the exit code
    if ($exitCodeStartComponentCleanup -eq 0) {
        Write-Output "The StartComponentCleanup operation completed successfully with exit code $exitCodeStartComponentCleanup."
    } elseif ($exitCodeStartComponentCleanup -eq 3010) {
        Write-Output "The StartComponentCleanup operation completed successfully and a restart is required with exit code $exitCodeStartComponentCleanup."
    } else {
        Write-Host "The StartComponentCleanup operation failed with exit code $exitCodeStartComponentCleanup." -ForegroundColor Red
    }
}

# https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e
# https://superuser.com/a/1600121
# %WinDir%\Logs\DISM\dism.log
# %WinDir%\Logs\CBS\CBS.log

function RestoreHealth {
    # Verifies and fixes any corruption in the Component Store by verifying its system file backups against known good copies from the Windows Update servers through hash comparison
    # Run the DISM command
    $processRestoreHealth = Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /NoRestart /Cleanup-Image /RestoreHealth" -Verb RunAs -PassThru

    # Wait for the process to exit
    $processRestoreHealth | Wait-Process

    # Get the exit code
    $exitCodeRestoreHealth = $processRestoreHealth.ExitCode

    # Check the exit code
    if ($exitCodeRestoreHealth -eq 0) {
        Write-Output "The RestoreHealth operation completed successfully with exit code $exitCodeRestoreHealth."
        return $true
    } elseif ($exitCodeRestoreHealth -eq 3010) {
        Write-Output "The RestoreHealth operation completed successfully and a restart is required with exit code $exitCodeRestoreHealth."
        return $true
    } else {
        Write-Host "The RestoreHealth operation failed with exit code $exitCodeRestoreHealth." -ForegroundColor Red
    }
    return $false
}

function CheckHealth {
    # The CheckHealth parameter checks whether the image has been flagged as corrupted by a failed process and whether the corruption can be repaired.
    # Run the DISM command
    $processCheckHealth = Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /NoRestart /Cleanup-Image /CheckHealth" -Verb RunAs -PassThru

    # Wait for the process to exit
    $processCheckHealth | Wait-Process

    # Get the exit code
    $exitCodeCheckHealth = $processCheckHealth.ExitCode

    # Check the exit code
    if ($exitCodeCheckHealth -eq 0) {
        Write-Output "The CheckHealth operation completed successfully with exit code $exitCodeCheckHealth."
        return $true
    } elseif ($exitCodeCheckHealth -eq 3010) {
        Write-Output "The CheckHealth operation completed successfully and a restart is required with exit code $exitCodeCheckHealth."
        return $true
    } else {
        Write-Host "The CheckHealth operation failed with exit code $exitCodeCheckHealth." -ForegroundColor Red
    }
    return $false
}

function ScanHealth {
    # The ScanHealth parameter scans the image for component store corruption. This operation will take several minutes.
    # Run the DISM command
    $processScanHealth = Start-Process -FilePath "Dism.exe" -ArgumentList "/Online /NoRestart /Cleanup-Image /ScanHealth" -Verb RunAs -PassThru

    # Wait for the process to exit
    $processScanHealth | Wait-Process

    # Get the exit code
    $exitCodeScanHealth = $processScanHealth.ExitCode

    # Check the exit code
    if ($exitCodeScanHealth -eq 0) {
        Write-Output "The ScanHealth operation completed successfully with exit code $exitCodeScanHealth."
        return $true
    } elseif ($exitCodeScanHealth -eq 3010) {
        Write-Output "The ScanHealth operation completed successfully and a restart is required with exit code $exitCodeScanHealth."
        return $true
    } else {
        Write-Host "The ScanHealth operation failed with exit code $exitCodeScanHealth." -ForegroundColor Red
    }
    return $false
}

function SfcScanNow {
    # SFC always assumes the Component Store is not corrupted and is why the DISM /RestoreHealth parameter should always be run prior to SFC; 
    # not doing so allows a corrupted Component Store to potentially replace a good system file with a corrupted one or fail to fix corruption within %WinDir% altogether

    # Verifies and fixes any corruption within %WinDir% by verifying against the known good copies within the Component Store through hash comparison
    # Run the SFC command
    $processScanNow = Start-Process -FilePath "Sfc.exe" -ArgumentList "/ScanNow" -Verb RunAs -PassThru

    # Wait for the process to exit
    $processScanNow | Wait-Process

    # Get the exit code
    $exitCodeScanNow = $processScanNow.ExitCode

    # Check the exit code
    # https://github.com/MicrosoftDocs/windowsserverdocs/issues/7391
    # Exit Code 0 
    # No integrity violations were found. This is indeed the ideal outcome, indicating all protected system files are healthy.

    # Exit Code 1
    # System File Checker found corrupt files and attempted to repair them. This doesn't necessarily guarantee successful repair. 
    # SFC checks if it has a cached copy of the healthy file and replaces the corrupt one. However, if the cached copy is also corrupt or unavailable, the repair may not be successful.

    # Exit Code 2
    # System File Checker found corrupt files but could not repair them. This usually means the tool lacks a healthy copy of the file or encounters permission issues preventing the replacement. 
    # It's crucial to investigate further and find alternative solutions for these unfixable files.
    if ($exitCodeScanNow -eq 0) {
        Write-Output "The ScanNow operation completed successfully with exit code $exitCodeScanNow."
    } else {
        Write-Host "The ScanNow operation failed with exit code $exitCodeScanNow." -ForegroundColor Red
    }
}

function GetDriveInfo {
    # Create a hash set to keep track of processed disk numbers
    $processedDisks = @{}

    # Iterate over each volume with a drive letter
    $volumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveType -ne "Removable"}

    # Create an array to hold the results
    $driveInfo = @()

    # Iterate through each volume
    foreach ($volume in $volumes) {
        # Get the partitions associated with the volume
        $partitions = Get-Partition | Where-Object { $_.AccessPaths -contains "$($volume.DriveLetter):\" }
        
        if ($partitions) {
            # Iterate over each partition
            foreach ($partition in $partitions) {
                # Get the disk associated with the partition
                $disk = Get-Disk -Number $partition.DiskNumber

                # Check if the disk is not USB and has not been processed yet
                if ($disk.BusType -ne "USB" -and -not $processedDisks.Contains($disk.Number)) {
                    # Add the disk number to the hash set
                    $processedDisks[$disk.Number] = $true

                    # Get the physical disk to obtain the MediaType
                    $physicalDisk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $disk.Number }

                    # Obtain disk health information
                    $DiskHealth = Get-StorageReliabilityCounter -PhysicalDisk (Get-PhysicalDisk -FriendlyName $physicalDisk.FriendlyName) | 
                                Select-Object Wear, ReadErrorsTotal, ReadErrorsUncorrected, ReadErrorsCorrected, WriteErrorsTotal, WriteErrorsUncorrected, WriteErrorscorrected, Temperature, TemperatureMax
                    
                    # Output the disk information
                    $driveInfo += [PSCustomObject]@{
                        DeviceId = $disk.Number
                        FriendlyName = $disk.FriendlyName
                        OperationalStatus = $disk.OperationalStatus
                        HealthStatus = $disk.HealthStatus
                        DriveLetter = $volume.DriveLetter
                        # BusType 17 = NVMe, 11 = SATA, 7 = USB. see https://learn.microsoft.com/de-de/windows-hardware/drivers/storage/msft-disk
                        # BusType = $disk.BusType
                        MediaType = $physicalDisk.MediaType
                        DiskWear = $DiskHealth.Wear
                        ReadErrorsTotal = $DiskHealth.ReadErrorsTotal
                        WriteErrorsTotal = $DiskHealth.WriteErrorsTotal
                    }
                }
            }
        }
    }
    return $driveInfo
}

function AnalyzeAndOptimizeDrives {
    param (
        [Parameter(Mandatory = $true)]
        [array]$driveInfo
    )

    # Define thresholds
    $MaxWearValue = 80
    $MaxRWErrors = 100

    $isVirtualMachine = GetMachineType
    if ($isVirtualMachine) {
        Write-Output "Virtualmachine detected.. Skipping defrag and trim"
        return
    }

    # Get SMART failure data once
    $DriveSMARTStatuses = Get-CimInstance -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | Where-Object { $_.PredictFailure -eq $true }

    # Check if a defrag is recommended
    # Iterate through each object in the results
    foreach ($drive in $driveInfo) {
        $DriveSMARTStatus = $DriveSMARTStatuses | Where-Object { $_.InstanceName -eq $drive.DeviceId }

        if ($DriveSMARTStatus) {
            Write-Output "SMART predicted failure detected with reason code $($DriveSMARTStatus.Reason) Skipping defrag and trim"
            return
        }

        if ($null -ne [int]$drive.DiskWear -and [int]$drive.DiskWear -ge $MaxWearValue) {
            Write-Output "Disk failure likely. Current wear value: $($drive.DiskWear), above threshold: $MaxWearValue% Skipping defrag and trim"
            return
        }

        if ($null -ne [int]$drive.ReadErrorsTotal -and [int]$drive.ReadErrorsTotal -ge $MaxRWErrors) {
            Write-Output "High number of read errors: $($drive.ReadErrorsTotal), above threshold: $MaxRWErrors Skipping defrag and trim"
            return
        }

        if ($null -ne [int]$drive.WriteErrorsTotal -and [int]$drive.WriteErrorsTotal -ge $MaxRWErrors) {
            Write-Output "High number of write errors: $($drive.WriteErrorsTotal), above threshold: $MaxRWErrors Skipping defrag and trim"
            return
        }

        if ($($drive.MediaType) -eq "SSD" -and $($drive.OperationalStatus) -eq "Online" -and $($drive.HealthStatus) -eq "Healthy") {
            # Get the instance of the Win32_Volume
            $getVolume = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$($drive.DriveLetter):'"

            # Invoke the DefragAnalysis method on the instance
            $defragAnalysis = Invoke-CimMethod -InputObject $getVolume -MethodName DefragAnalysis

            # Display the result
            $isDefragRecommended = $defragAnalysis.DefragRecommended

            # https://learn.microsoft.com/en-us/powershell/module/storage/optimize-volume?view=windowsserver2022-ps
            if ($isDefragRecommended -eq "True") {
                Write-Output "Trim now $($drive.FriendlyName)"
                # Call the function to check TRIM status
                $isTrim = Get-TrimStatus
                if (-not($isTrim)) {
                    # Enable trim
                    fsutil behavior set DisableDeleteNotify 0
                }
                Optimize-Volume -DriveLetter $($drive.DriveLetter) -ReTrim -Verbose
            }
        } elseif ($($drive.MediaType) -eq "HDD" -and $($drive.OperationalStatus) -eq "Online" -and $($drive.HealthStatus) -eq "Healthy") {
            # Get the instance of the Win32_Volume
            $getVolume = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$($drive.DriveLetter):'"

            # Invoke the DefragAnalysis method on the instance
            $defragAnalysis = Invoke-CimMethod -InputObject $getVolume -MethodName DefragAnalysis

            # Display the result
            $isDefragRecommended = $defragAnalysis.DefragRecommended

            if ($isDefragRecommended -eq "True") {
                Write-Output "Defrag now $($drive.FriendlyName)"
                Optimize-Volume -DriveLetter $($drive.DriveLetter) -Defrag -Verbose
            }
        }
    }
}

function RebuildingPerformanceCounters {
    if (Test-Path "$env:SystemRoot\SYSTEM32\lodctr.exe" -PathType Leaf) {
        Write-Output "Rebuild Performance Counters for x32 Systems"
        Start-Process -FilePath "$env:SystemRoot\SYSTEM32\lodctr.exe" -ArgumentList "/R" -Wait
    }
    if (Test-Path "$env:SystemRoot\sysWOW64\lodctr.exe" -PathType Leaf) {
        Write-Output "Rebuild Performance Counters for x64 Systems"
        Start-Process -FilePath "$env:SystemRoot\sysWOW64\lodctr.exe" -ArgumentList "/R" -Wait
    }
    if (Test-Path "$env:SystemRoot\SYSTEM32\wbem\WinMgmt.exe" -PathType Leaf) {
        Write-Output "Resynchronization of performance counters"
        Start-Process -FilePath "$env:SystemRoot\SYSTEM32\wbem\WinMgmt.exe" -ArgumentList "/RESYNCPERF" -Wait
    }
    Write-Output "Restarting pla Service"
    Stop-Service -Name "pla" -Force -ErrorAction SilentlyContinue
    Start-Service -Name "pla" -ErrorAction SilentlyContinue

    Write-Output "Restarting winmgmt Service"
    Stop-Service -Name "Winmgmt" -Force -ErrorAction SilentlyContinue
    Start-Service -Name "Winmgmt" -ErrorAction SilentlyContinue
}

function WinsatFormal {
    # https://www.deploymentresearch.com/why-adding-winsat-formal-to-your-task-sequence-can-be-a-shiny-thing-to-do/
    if (Test-Path "$env:SystemRoot\SYSTEM32\WinSAT.exe" -PathType Leaf) {
        Start-Process -FilePath "$env:SystemRoot\SYSTEM32\WinSAT.exe" -ArgumentList "formal -restart clean" -Wait
    }
}

# Start Logging
Start-Transcript -Path "$CleanupLog"

Write-Host "`n"
Write-Host "######################################################## CLEAN STUFF ########################################################" -ForegroundColor Green
Write-Host "`n"

# Get the drive where Windows is installed
$windowsDriveRoot = ([System.IO.Path]::GetPathRoot($env:SystemRoot))

# Capture initial free space
$initialFreeSpaceBytes = Get-FreeSpace -driveRoot $windowsDriveRoot
$initialFreeSpaceGB = [math]::round($initialFreeSpaceBytes / 1GB, 2)
$initialFreeSpaceMB = [math]::round($initialFreeSpaceBytes / 1MB, 2)
Write-Host "Initial Free Space: $initialFreeSpaceGB GB ($initialFreeSpaceMB MB) ($initialFreeSpaceBytes Bytes)" -ForegroundColor Green

Write-Host "Removing the current Windows Clean Manager state flags" -ForegroundColor Green
Remove-StateFlags0112 -rootKey "HKEY_LOCAL_MACHINE" -subKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

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

Write-Host "Clear the print queue" -ForegroundColor Green
ClearPrintQueue

# Call the function
Write-Host "Getting pending windows updates" -ForegroundColor Green
$updatesAvailable = Get-PendingWindowsUpdates
if ($updatesAvailable) {
    Write-Output "There are pending or missing Windows updates."
} else {
    Write-Output "System is up to date."

    # Define the path to the SoftwareDistribution Download folder
    $softwareDistributionDownloadFolderPath = "$env:WINDIR\SoftwareDistribution\Download"
    # Call the function to clear the Download folder
    Write-Host "Clear the SoftwareDistributionDownloadFolder" -ForegroundColor Green
    Clear-SoftwareDistributionDownloadFolder -FolderPath $softwareDistributionDownloadFolderPath
}

Write-Host "Removing .etl files" -ForegroundColor Green
DeleteEtlFiles

Write-Host "Removing temp files" -ForegroundColor Green
DeleteTempFiles

Write-Host "Removing .rbs files" -ForegroundColor Green
DeleteRbsFiles

Write-Host "Removing log files" -ForegroundColor Green
DeleteLogFiles

Write-Host "Clean windows error reportings" -ForegroundColor Green
CleanWindowsErrorReporting

Write-Host "Removing .dmp files" -ForegroundColor Green
DeleteDmpFiles

Write-Host "Defrag databases" -ForegroundColor Green
DefragDatabases

Write-host "Searching for duplicate files in users download folder" -ForegroundColor Green
# Delete duplicate files in users download folder
# Define source directory
$srcDir = "$env:USERPROFILE\Downloads"

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

Write-Host "Clean old drivers and devices" -ForegroundColor Green
CleanOldDriversAndDevices

Write-Host "Running windows cleanmanager" -ForegroundColor Green
CleanManager

Write-Host "Clear RecycleBin" -ForegroundColor Green
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Write-Host "Running DISM StartComponentCleanup" -ForegroundColor Green
StartComponentCleanup

# Reset LongPathsEnabled to system default value
if ($global:currentlongPathsEnabledValue -eq 0) {
    New-ItemProperty -Path $longPathsEnabledRegKey -Force -Name "LongPathsEnabled" -PropertyType "Dword" -Value "0"
}

# Capture free space after cleaning
$finalFreeSpaceBytes = Get-FreeSpace -driveRoot $windowsDriveRoot
$finalFreeSpaceGB = [math]::round($finalFreeSpaceBytes / 1GB, 2)
$finalFreeSpaceMB = [math]::round($finalFreeSpaceBytes / 1MB, 2)

Write-Host "Final Free Space: $finalFreeSpaceGB GB ($finalFreeSpaceMB MB) ($finalFreeSpaceBytes Bytes)" -BackgroundColor Green

# Calculate reclaimed space
$reclaimedSpaceBytes = $finalFreeSpaceBytes - $initialFreeSpaceBytes
$reclaimedSpaceGB = [math]::round($reclaimedSpaceBytes / 1GB, 2)
$reclaimedSpaceMB = [math]::round($reclaimedSpaceBytes / 1MB, 2)

Write-Host "Reclaimed Space: $reclaimedSpaceGB GB ($reclaimedSpaceMB MB) ($reclaimedSpaceBytes Bytes)" -BackgroundColor Green

Write-Host "`n"
Write-Host "######################################################## CLEAN STUFF ########################################################" -ForegroundColor Green
Write-Host "`n"

Write-Host "`n"
Write-Host "######################################################## FIX STUFF ##########################################################" -ForegroundColor Green
Write-Host "`n"

# Write-Host "Running DISM CheckHealth" -ForegroundColor Green
# $isCheckHealth = CheckHealth

# Write-Host "Running DISM ScanHealth" -ForegroundColor Green
# $isScanHealth = ScanHealth

# if (-not($isScanHealth)) {
    # Write-Host "Running DISM RestoreHealth" -ForegroundColor Green
    # $isRestoreHealth = RestoreHealth
# }

# if ($isScanHealth -or $isRestoreHealth) {
    # Write-Host "Running SFC ScanNow" -ForegroundColor Green
    # SfcScanNow
# }

# Why do we need ScanHealth when RestoreHealth includes ScanHealth ?
Write-Host "Running DISM RestoreHealth" -ForegroundColor Green
$isRestoreHealth = RestoreHealth

if ($isRestoreHealth) {
    Write-Host "Running SFC ScanNow" -ForegroundColor Green
    SfcScanNow
}

Write-Host "Getting information about the disks" -ForegroundColor Green
# Call the function and store the result
$driveInfoResult = GetDriveInfo

Write-Host "Trim / Defrag SSD, HDD" -ForegroundColor Green
AnalyzeAndOptimizeDrives -driveInfo $driveInfoResult

Write-Host "Rebuilding performance counters" -ForegroundColor Green
RebuildingPerformanceCounters

Write-Host "Running winsat formal" -ForegroundColor Green
WinsatFormal

Write-Host "`n"
Write-Host "######################################################## FIX STUFF ##########################################################" -ForegroundColor Green
Write-Host "`n"

# Stop Logging
Stop-Transcript

Write-Host "Cleaning complete" -ForegroundColor Green
Write-Host "`n"
Write-Host "Would you like to restart now? (Recommended)" -ForegroundColor Yellow
$Readhost = Read-Host "(Y/N) Default is no"
Switch ($ReadHost) {
    Y { Write-Output "Do a clean restart now"; Start-Sleep -Seconds 2; Start-Process -FilePath "Shutdown.exe" -ArgumentList "/g /f /t 0" -Wait }
    N {}
    Default {}
}

Write-Host "Press any key to exit..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
exit
