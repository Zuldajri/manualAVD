Param(
  [string] $TenantId,
  [string] $SubscriptionId,
  [string] $aadClientId,
  [string] $aadClientSecret,
  [string] $rdshGalleryImageSKU,
  [string] $ResourceGroupName,
  [string] $StorageAccountName,
  [string] $fileShareName,
  [string] $StorageAccountKey,
  [string] $domainName,
  [string] $domainType,
  [string] $profileType,
  [string] $ObjectIDGroupUser,
  [string] $ObjectIDGroupAdmin,
  [string] $useAVDOptimizer,
  [string] $useScalingPlan,
  [string] $existingDomainUsername,
  [string] $domainAdminPassword,
  [string] $adComputerName,
  [string] $installTeams
)


$osDrive = ((Get-WmiObject Win32_OperatingSystem).SystemDrive).TrimEnd(":")
$size = (Get-Partition -DriveLetter $osDrive).Size
$maxSize = (Get-PartitionSupportedSize -DriveLetter $osDrive).SizeMax
if ($size -lt $maxSize){
     Resize-Partition -DriveLetter $osDrive -Size $maxSize
}


#Step 1
#Module and Connection
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PowerShellGet -Force -AllowClobber
Install-Module -Name Az -force -AllowClobber
Import-Module Az -Force

#Connection Needed for Azure 
$azurePassword = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($aadClientId , $azurePassword)
Connect-AzAccount -Credential $psCred -TenantId $TenantId  -ServicePrincipal
Select-AzSubscription -SubscriptionId $SubscriptionId


if ($rdshGalleryImageSKU -eq '2016-Datacenter'){
    #enable TLS 1.2 to work for Windows Server 2016 environments
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
    sleep 5
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
    sleep 5
}

#Step 2
#Variable to not modify
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$UserGroupName = "AVD-Users"
$AdminGroupName = "AVD-Admin"
$rolenameAdmin = "Storage File Data SMB Share Elevated Contributor"
$rolenameUser = "Storage File Data SMB Share Contributor"
$AccountType = "ComputerAccount"
$DirectoryID= "T:\Profiles"
$Directory= "Profiles"
$OrganizationalUnitDistinguishedName= ""
$RBACAdmin1 = "Desktop Virtualization Application Group Contributor"
$RBACAdmin2 = "Desktop Virtualization Contributor"
$RBACAdmin3 = "Desktop Virtualization Host Pool Contributor"
$RBACAdmin4 = "Desktop Virtualization Session Host Operator"
$RBACAdmin5 = "Desktop Virtualization User Session Operator"
$RBACAdmin6 = "Desktop Virtualization Workspace Contributor"
$RBACUser1 = "Desktop Virtualization User"
$hostname = hostname
$fulluser = "$($domainName)\$($existingDomainUsername)"
$secpasswd = ConvertTo-SecureString $domainAdminPassword -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential($fulluser, $secpasswd)





#Step 8 FSLogix Variables

$LocalAVDpath = "C:\temp\AVD"
$FSLogixURI  = "https://aka.ms/fslogix_download"
$FSInstaller = "FSLogixAppsSetup.zip"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$connectionString = '\\' + $StorageAccountName + '.file.core.windows.net\userprofiles\Profiles'




#Step 8 Test/Create Temp Directory
New-Item -Path "C:\temp\New-AVDSessionHost.log" -ItemType File
if((Test-Path C:\temp) -eq $false) {
    Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Create C:\temp Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating temp directory"
    New-Item -Path c:\temp -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "C:\temp Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "temp directory already exists"
}
if((Test-Path $LocalAVDpath) -eq $false) {
    Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Create C:\temp\AVD Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating c:\temp\AVD directory"
    New-Item -Path $LocalAVDpath -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "C:\temp\AVD Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "c:\temp\AVD directory already exists"
}

Add-Content `
-LiteralPath C:\temp\New-AVDSessionHost.log `
"
ProfilePath       = $connectionString
"

#Step 8    Download AVD Components    

Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Downloading FSLogix"
Invoke-WebRequest -Uri $FSLogixURI -OutFile "$LocalAVDpath\$FSInstaller"

#Step 9    Prep for WVD Install  

Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Unzip FSLogix"
Expand-Archive `
    -LiteralPath "C:\temp\AVD\$FSInstaller" `
    -DestinationPath "$LocalAVDpath\FSLogix" `
    -Force `
    -Verbose
cd $LocalAVDpath 
Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "UnZip FXLogix Complete"

#Step 10    FSLogix Install

Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Installing FSLogix"
$fslogix_deploy_status = Start-Process `
    -FilePath "$LocalAVDpath\FSLogix\x64\Release\FSLogixAppsSetup.exe" `
    -ArgumentList "/install /quiet /norestart" `
    -Wait `
    -Passthru

sleep 10

#Step 11    FSLogix Local Group Policy available

mv C:\temp\AVD\FSLogix\fslogix.adml C:\Windows\PolicyDefinitions\en-US\fslogix.adml
mv C:\temp\AVD\FSLogix\fslogix.admx C:\Windows\PolicyDefinitions\fslogix.admx


#Step 12    FSLogix User Profile Settings

Add-Content -LiteralPath C:\temp\New-AVDSessionHost.log "Configure FSLogix Profile Settings"
Push-Location 
Set-Location HKLM:\SOFTWARE\
New-Item `
    -Path HKLM:\SOFTWARE\FSLogix `
    -Name Profiles `
    -Value "" `
    -Force
New-Item `
    -Path HKLM:\Software\FSLogix\Profiles\ `
    -Name Apps `
    -Force
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "Enabled" `
    -Type "Dword" `
    -Value "1"
New-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "VHDLocations" `
    -Value $connectionString `
    -PropertyType MultiString `
    -Force
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "SizeInMBs" `
    -Type "Dword" `
    -Value "30720"
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "IsDynamic" `
    -Type "Dword" `
    -Value "1"
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "VolumeType" `
    -Type String `
    -Value "vhdx"
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "ConcurrentUserSessions" `
    -Type "Dword" `
    -Value "1"
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "FlipFlopProfileDirectoryName" `
    -Type "Dword" `
    -Value "1" 
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "SIDDirNamePattern" `
    -Type String `
    -Value "%username%%sid%"
Set-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "SIDDirNameMatch" `
    -Type String `
    -Value "%username%%sid%" 
New-ItemProperty `
    -Path HKLM:\SOFTWARE\FSLogix\Profiles `
    -Name "DeleteLocalProfileWhenVHDShouldApply" `
    -PropertyType "DWord" `
    -Value 1
Pop-Location


#Step 13    Add Defender Exclusions for FSLogix

$filelist = `
"%ProgramFiles%\FSLogix\Apps\frxdrv.sys", `
"%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys", `
"%ProgramFiles%\FSLogix\Apps\frxccd.sys", `
"%TEMP%\*.VHD", `
"%TEMP%\*.VHDX", `
"%Windir%\TEMP\*.VHD", `
"%Windir%\TEMP\*.VHDX", `
"\\$StorageAccountName.file.core.windows.net\share\*.VHD", `
"\\$StorageAccountName.file.core.windows.net\share\*.VHDX"

$processlist = `
"%ProgramFiles%\FSLogix\Apps\frxccd.exe", `
"%ProgramFiles%\FSLogix\Apps\frxccds.exe", `
"%ProgramFiles%\FSLogix\Apps\frxsvc.exe"

Foreach($item in $filelist){
    Add-MpPreference -ExclusionPath $item}
Foreach($item in $processlist){
    Add-MpPreference -ExclusionProcess $item}




if ($profileType -eq 'Graphics'){
    #Step 12    enable GPU Rendering / sets AVC Encoding / Full Screen Rendering
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v bEnumerateHWBeforeSW  /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v AVC444ModePreferred  /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v AVCHardwareEncodePreferred  /t REG_DWORD /d 1 /f

    sleep 10
    gpupdate.exe /force
    sleep 10
}

#Step 14    FslogixTeamsExclusions

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
#Directory Creation for Teams Exclusion
$DirectoryT= "Teams"
$connectionString2= "\\$StorageAccountName.file.core.windows.net\$fileShareName\$DirectoryT"

#Fslogix regedit configuration
Push-Location 
Set-Location HKLM:\SOFTWARE\

New-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "RedirXMLSourceFolder" `
    -Value $connectionString2 `
    -PropertyType MultiString `
    -Force 




#Step 15    Teams installation

if ($installTeams -eq 'true'){
    if ($rdshGalleryImageSKU -like '*Datacenter'){

        #regedit teams for wvd
        New-Item -Path HKLM:\SOFTWARE\Microsoft -Name "Teams" 
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Teams -Name "IsWVDEnvironment" -Type "Dword" -Value "1"
        Start-Sleep -s 5
    
        #Variables
        $CSource = "https://aka.ms/vs/16/release/vc_redist.x64.exe"
        $RDWRedirectorSource = "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE4AQBt"
        $TeamsSource = "https://teams.microsoft.com/downloads/desktopurl?env=production&plat=windows&arch=x64&managedInstaller=true&download=true"
        $Clocation = "C:\temp\vc_redist.x64.exe"
        $RDWRedirectionLocation = "C:\temp\MsRdcWebRTCSvc_HostSetup_1.0.2006.11001_x64.msi"
        $TeamsLocation = "C:\temp\Teams_windows_x64.msi"


        #Download C++ Runtime
        invoke-WebRequest -Uri $Csource -OutFile $Clocation
        Start-Sleep -s 5
        #Download RDCWEBRTCSvc
        invoke-WebRequest -Uri $RDWRedirectorSource -OutFile $RDWRedirectionLocation
        Start-Sleep -s 5
        #Download Teams 
        invoke-WebRequest -Uri $TeamsSource -OutFile $TeamsLocation
        Start-Sleep -s 5

        #Install C++ runtime
        Start-Process -FilePath $Clocation -ArgumentList '/q', '/norestart'
        Start-Sleep -s 10
        #Install MSRDCWEBTRCSVC
        msiexec /i $RDWRedirectionLocation /q /n
        Start-Sleep -s 10
        # Install Teams
        msiexec /i $TeamsLocation /l*v teamsinstall.txt ALLUSER=1 ALLUSERS=1 /q
        Start-Sleep -s 10
    }
}

if ($useAVDOptimizer -eq 'true'){
#Step 16    WVD Optimization


    $Optimizations = "All"

#    Download WVD Optimizer    

    New-Item -Path C:\ -Name Optimize -ItemType Directory -ErrorAction SilentlyContinue
    $LocalPath = "C:\Optimize\"
    $WVDOptimizeURL = 'https://github.com/Zuldajri/AVD/blob/main/Virtual-Desktop-Optimization-Tool-main.zip?raw=true'
    $WVDOptimizeInstaller = "Windows_10_VDI_Optimize-master.zip"
    Invoke-WebRequest `
        -Uri $WVDOptimizeURL `
        -OutFile "$Localpath$WVDOptimizeInstaller"

#    Prep for WVD Optimize    
    Expand-Archive `
        -LiteralPath "C:\Optimize\Windows_10_VDI_Optimize-master.zip" `
        -DestinationPath "$Localpath" `
        -Force `
        -Verbose

#    Run WVD Optimize Script    
    New-Item -Path "C:\Optimize\install.log" -ItemType File -Force
    add-content c:\Optimize\install.log "Starting Optimizations"  
    & C:\Optimize\Virtual-Desktop-Optimization-Tool-main\Win10_VirtualDesktop_Optimize.ps1 -Optimizations $Optimizations -AcceptEULA -Verbose
    Start-Sleep -s 15

}
