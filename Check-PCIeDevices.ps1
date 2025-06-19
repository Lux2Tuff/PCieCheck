# Check-PCIeDevices.ps1
# PowerShell script to enumerate PCIe devices, retrieve device class and hardware IDs,
# and cross-reference against known DMA device spoof patterns used by PCILeech/LeechCore-based cheats.

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    exit 1
}

# Define log file path
$LogFile = "$env:TEMP\PCIeDeviceCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to log messages
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host $Message
}

# Define known DMA device spoof patterns (VendorID:DeviceID and Device Class)
# Based on common PCIe devices and spoofed IDs from PCILeech-related hardware
# Example sources: PCILeech GitHub, dma.lystic.dev, and community reports
$SuspiciousDMAPatterns = @(
    @{ VendorID = "10EE"; DeviceID = "0666"; Class = "FF00"; Description = "Xilinx FPGA (Screamer PCIe Squirrel stock)" }, # Common FPGA used in PCILeech
    @{ VendorID = "1D0F"; DeviceID = "*"; Class = "FF00"; Description = "Amazon FPGA (Potential custom DMA firmware)" }, # Wildcard for DeviceID
    @{ VendorID = "10EE"; DeviceID = "*"; Class = "0C03"; Description = "Spoofed USB Controller (PCILeech USB3380 emulation)" },
    @{ VendorID = "8086"; DeviceID = "*"; Class = "FF00"; Description = "Intel FPGA (Potential spoofed DMA device)" },
    @{ VendorID = "12D8"; DeviceID = "*"; Class = "FF00"; Description = "PLX Technology USB3380 (PCILeech legacy hardware)" },
    @{ VendorID = "*"; DeviceID = "*"; Class = "FF00"; Description = "Unknown Device Class (Common for FPGA-based DMA)" } # Catch-all for unclassified devices
)

# Function to normalize hardware IDs for comparison
function Normalize-HardwareID {
    param ([string]$ID)
    $ID = $ID.ToUpper()
    if ($ID -match "^PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})") {
        return @{ VendorID = $Matches[1]; DeviceID = $Matches[2] }
    }
    return $null
}

# Function to check if a device matches a suspicious pattern
function Test-SuspiciousDevice {
    param (
        [string]$VendorID,
        [string]$DeviceID,
        [string]$Class,
        [array]$Patterns
    )
    foreach ($Pattern in $Patterns) {
        $VendorMatch = ($Pattern.VendorID -eq "*" -or $Pattern.VendorID -eq $VendorID)
        $DeviceMatch = ($Pattern.DeviceID -eq "*" -or $Pattern.DeviceID -eq $DeviceID)
        $ClassMatch = ($Pattern.Class -eq $Class)
        if ($VendorMatch -and $DeviceMatch -and $ClassMatch) {
            return $Pattern.Description
        }
    }
    return $null
}

# Start logging
Write-Log "Starting PCIe device check..."

try {
    # Enumerate all PCIe devices using Get-PnpDevice
    $PCIeDevices = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "PCI\*" } | 
        Select-Object Name, Class, HardwareID, InstanceId, Status

    if (-not $PCIeDevices) {
        Write-Log "No PCIe devices found."
        exit 0
    }

    Write-Log "Found $($PCIeDevices.Count) PCIe device(s). Analyzing..."

    # Initialize results array
    $Results = @()

    foreach ($Device in $PCIeDevices) {
        $DeviceName = $Device.Name
        $DeviceClass = $Device.Class
        $HardwareIDs = $Device.HardwareID
        $InstanceId = $Device.InstanceId
        $Status = $Device.Status

        # Get the first hardware ID for parsing VendorID and DeviceID
        $PrimaryHardwareID = $HardwareIDs | Select-Object -First 1
        $NormalizedID = Normalize-HardwareID -ID $PrimaryHardwareID

        if ($NormalizedID) {
            $VendorID = $NormalizedID.VendorID
            $DeviceID = $NormalizedID.DeviceID
            # Retrieve Device Class Code from WMI (BaseClass, SubClass, ProgIF)
            $WmiDevice = Get-WmiObject -Class Win32_PnPEntity | 
                Where-Object { $_.PNPDeviceID -eq $InstanceId } | 
                Select-Object -First 1
            $ClassCode = if ($WmiDevice) { 
                $BaseClass = "{0:X2}" -f $WmiDevice.BaseClass
                $SubClass = "{0:X2}" -f $WmiDevice.SubClass
                $ProgIF = "{0:X2}" -f $WmiDevice.ProgIF
                "$BaseClass$SubClass$ProgIF".Substring(0,4)
            } else { 
                "UNKNOWN" 
            }

            # Check for suspicious patterns
            $SuspiciousMatch = Test-SuspiciousDevice -VendorID $VendorID -DeviceID $DeviceID -Class $ClassCode -Patterns $SuspiciousDMAPatterns

            $Result = [PSCustomObject]@{
                DeviceName    = $DeviceName
                VendorID      = $VendorID
                DeviceID      = $DeviceID
                ClassCode     = $ClassCode
                DeviceClass   = $DeviceClass
                HardwareID    = $PrimaryHardwareID
                Status        = $Status
                Suspicious    = if ($SuspiciousMatch) { $SuspiciousMatch } else { "None" }
            }
            $Results += $Result

            Write-Log "Device: $DeviceName | VendorID: $VendorID | DeviceID: $DeviceID | ClassCode: $ClassCode | Suspicious: $($Result.Suspicious)"
        } else {
            Write-Log "Device: $DeviceName | HardwareID: $PrimaryHardwareID | Could not parse VendorID/DeviceID"
        }
    }

    # Output results to console and log
    $Results | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }

    # Highlight suspicious devices
    $SuspiciousDevices = $Results | Where-Object { $_.Suspicious -ne "None" }
    if ($SuspiciousDevices) {
        Write-Log "WARNING: $($SuspiciousDevices.Count) suspicious device(s) detected!"
        $SuspiciousDevices | ForEach-Object {
            Write-Log "Suspicious Device: $($_.DeviceName) - $($_.Suspicious)"
        }
    } else {
        Write-Log "No suspicious devices detected."
    }

    Write-Log "Check completed. Log saved to: $LogFile"
}
catch {
    Write-Log "Error occurred: $($_.Exception.Message)"
    exit 1
}