<#
.SYNOPSIS
Executes Kape and Kape modules on a remote device and archives output.

.DESCRIPTION
Collects forensic information from a remote machine, processes modules for additional info. Forensic data is archived to the SOC share.

.PARAMETER ComputerName
The device to investigate.

.PARAMETER Collect
Data to collect. All, Basic, Basic+.

.PARAMATER Save
Optional. Location to save forensic data.

.EXAMPLE
Invoke-Kape.ps1 -ComputerName Win10Desktop -Collect Basic

.EXAMPLE
Invoke-Kape.ps1 -ComputerName Win10Desktop -Collect Basic -Save C:\users\soc\desktop\evidence\

.AUTHOR
Keyboardcrunch
Created: 8/2/2019
#>

param (
    [string]$ComputerName = $(throw "-ComputerName is required."),
    [string]$Save = "\\SecurityOperations\EVIDENCE",
    [string]$KapePackage = "\\SecurityOperations\Incident Response\Packages\kapecollector.zip",
    [ValidateSet('All','Basic','Basic+')]
    [string]$Collect = $(throw "-collect is required.")
)

$ErrorActionPreference = "Continue"

$Banner = "
  _____                 _                                    
  \_   \_ ____   _____ | | _____        /\ /\__ _ _ __   ___ 
   / /\/ '_ \ \ / / _ \| |/ / _ \_____ / //_/ _` | '_ \ / _ \
/\/ /_ | | | \ V / (_) |   <  __/_____/ __ \ (_| | |_) |  __/
\____/ |_| |_|\_/ \___/|_|\_\___|     \/  \/\__,_| .__/ \___|
                                                 |_|         "
Write-Host $Banner -ForegroundColor Cyan



If (Test-Connection -ComputerName $ComputerName -Count 2 -ErrorAction SilentlyContinue) {
    Write-Host "`t[ INFO ][ Deploying collector..." -ForegroundColor Yellow
    Copy-Item $KapePackage -Destination "\\$ComputerName\C$\Windows\Temp\kapecollector.zip" -Force
    
    # Staging
    Write-Host "`t[ INFO ][ Extracting collector..." -ForegroundColor Yellow
    $session = New-PSSession -ComputerName $ComputerName
    Invoke-Command -Session $session -ScriptBlock { 
        # Ensure kape folders don't exist
        Remove-Item -Path "C:\Windows\Temp\kape\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\kapecollector\" -Recurse -Force -ErrorAction SilentlyContinue

        # Extract package
        Expand-Archive -Path "C:\Windows\Temp\kapecollector.zip" -DestinationPath "C:\Windows\Temp\" -Force
        Remove-Item -Path "C:\Windows\Temp\kapecollector.zip" -Force -ErrorAction SilentlyContinue
    }

    # Execution
    Write-Host "`t[ INFO ][ Executing..." -ForegroundColor Yellow
    Switch ($Collect) {
        "All" {
            Invoke-Command -Session $session -ScriptBlock { 
                Set-Location "C:\Windows\Temp\kapecollector\"
                $CollectCommand = "--tsource C: --tdest C:\windows\temp\kape\collected --tflush --target !ALL --mdest C:\windows\temp\kape\processed\ --mflush --module AmcacheParser,ARPCache,autoruns,Detailed-Network-Share-Access,DNSCache,EvtxECmd,Get-NetworkConnection,IPConfig,NBTStat_NetBIOS_Cache,NBTStat_NetBIOS_Sessions,NetStat,NetworkDetails,PWSH-Get-ProcessList,RDP-Usage-events,RoutingTable,WindowsEventLogs,WxTCmd,PECmd --mef csv"
                Start-Process -FilePath "C:\Windows\Temp\kapecollector\kape.exe" -ArgumentList $CollectCommand -Wait
            }
        }
        "Basic" {
            Invoke-Command -Session $session -ScriptBlock { 
                Set-Location "C:\Windows\Temp\kapecollector\"
                $CollectCommand = "--tsource C: --tdest C:\windows\temp\kape\collected --tflush --target !BasicCollection --mdest C:\windows\temp\kape\processed\ --mflush --module AmcacheParser,ARPCache,autoruns,Detailed-Network-Share-Access,DNSCache,EvtxECmd,Get-NetworkConnection,IPConfig,NBTStat_NetBIOS_Cache,NBTStat_NetBIOS_Sessions,NetStat,NetworkDetails,PWSH-Get-ProcessList,RDP-Usage-events,RoutingTable,WindowsEventLogs,WxTCmd,PECmd --mef csv"
                Start-Process -FilePath "C:\Windows\Temp\kapecollector\kape.exe" -ArgumentList $CollectCommand -Wait
            }
        }
        "Basic+" {
            Invoke-Command -Session $session -ScriptBlock { 
                Set-Location "C:\Windows\Temp\kapecollector\"
                $CollectCommand = "--tsource C: --tdest C:\windows\temp\kape\collected --tflush --target Amcache,Chrome,CiscoJabber,CombinedLogs,Edge,EvidenceOfExecution,Firefox,InternetExplorer,McAfee_ePO,MOF,ScheduledTasks,StartupInfo,USBDevicesLogs,WBEM,WebBrowsers,WER,WindowsFirewall --mdest C:\windows\temp\kape\processed\ --mflush --module AmcacheParser,ARPCache,autoruns,Detailed-Network-Share-Access,DNSCache,EvtxECmd,Get-NetworkConnection,IPConfig,NBTStat_NetBIOS_Cache,NBTStat_NetBIOS_Sessions,NetStat,NetworkDetails,PWSH-Get-ProcessList,RDP-Usage-events,RoutingTable,WindowsEventLogs,WxTCmd,PECmd --mef csv"
                Start-Process -FilePath "C:\Windows\Temp\kapecollector\kape.exe" -ArgumentList $CollectCommand -Wait
            }
        }
    }

    # Wrap-up
    Write-Host "`t[ INFO ][ Compressing evidence..." -ForegroundColor Yellow
    Invoke-Command -Session $session -ScriptBlock { 
        # Archive collected data
        $ArchiveName = "$(hostname)-kape.zip"
        Compress-Archive -Path "C:\Windows\Temp\kape\" -DestinationPath "C:\Windows\Temp\$ArchiveName" -CompressionLevel Optimal

        # Cleanup
        Remove-Item -Path "C:\Windows\Temp\kapecollector\" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\Temp\kape\" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
	# Collect archive file
    Write-Host "`t[ INFO ][ Archiving evidence..." -ForegroundColor Yellow
    Move-Item -Path "\\$ComputerName\C$\Windows\Temp\$ComputerName-kape.zip" -Destination $Save

    # Session cleanup
    Remove-PSSession -Session $session
    Write-Host "`t[ INFO ][ Done!" -ForegroundColor Green
} Else {
    Write-Host "$ComputerName is offline!" -ForegroundColor Red
}
