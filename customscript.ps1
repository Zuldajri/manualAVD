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
  [string] $useAVDOptimizer,
  [string] $useScalingPlan,
  [string] $installTeams
)


#Step 1
#Module and Connection
Install-Module AZ
Import-Module AZ
Install-Module azuread
Import-Module azuread
#Connection Needed for Azure 
$azurePassword = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($aadClientId , $azurePassword)
Connect-AzAccount -Credential $psCred -TenantId $TenantId  -ServicePrincipal
Select-AzSubscription -SubscriptionId $SubscriptionId
#ADGroup Creation
if (!(Get-AzADGroup -DisplayName "AVD-Users")){New-AzADGroup -Description "AVD-Users" -DisplayName "AVD-Users" -MailNickName "AVD-Users"}
if (!(Get-AzADGroup -DisplayName "AVD-Admin")){New-AzADGroup -Description "AVD-Admin" -DisplayName "AVD-Admin" -MailNickName "AVD-Admin"}

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
$AzFileSource = "https://github.com/Zuldajri/AVD/blob/main/AzFilesHybrid.zip?raw=true"
$locationAzFiledownload = "C:\AzFilesHybrid.zip"
$folder = "C:\AzFileHybrid"
$UserGroupName = "AVD-Users"
$AdminGroupName = "AVD-Admin"
$ObjectIDGroupUser = (Get-AzADGroup -DisplayName $UserGroupName).id
$ObjectIDGroupAdmin = (Get-AzADGroup -DisplayName $AdminGroupName).id
$rolenameAdmin = "Storage File Data SMB Share Elevated Contributor"
$rolenameUser = "Storage File Data SMB Share Contributor"
$AccountType = "ComputerAccount"
$DirectoryID= "T:\Profiles"
$Directory= "Profiles"
$OrganizationalUnitDistinguishedName= ""



if ($domainType -eq 'AD'){
    #Step 3
    #Prepare the Join
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
    #Folder Creation for Unzip
    New-Item -Path $folder -ItemType Directory
    #Download AzFile and Unzip AzFile
    Invoke-WebRequest -Uri $AzFileSource -OutFile $locationAzFiledownload
    Expand-Archive D:\AzFilesHybrid.zip -DestinationPath D:\AzFileHybrid
    #Set the Location
    cd D:\AzFileHybrid
    # Navigate to where AzFilesHybrid is unzipped and stored and run to copy the files into your path
    .\CopyToPSPath.ps1
    #Import AzFilesHybrid module
    Import-Module -Name AzFilesHybrid

    #Step 4
    # Register the target storage account with your active directory environment
    Import-Module -Name AzFilesHybrid
    Join-AzStorageAccountForAuth `
        -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -DomainAccountType $AccountType `
        -OrganizationalUnitDistinguishedName $OrganizationalUnitDistinguishedName

    #Confirm the feature is enabled
    $storageaccount = Get-AzStorageAccount `
        -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName

    $storageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
    $storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
}


#Step 4
#Add the Azure Right to the storage Account
$FileShareContributorRole = Get-AzRoleDefinition $rolenameAdmin 
#Use one of the built-in roles: Storage File Data SMB Share Reader, Storage File Data SMB Share Contributor, Storage File Data SMB Share Elevated Contributor
#Constrain the scope to the target file share
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$fileShareName"
#Assign the custom role to the target identity with the specified scope.
New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
#Get the name of the custom role
$FileShareContributorRole = Get-AzRoleDefinition $rolenameUser 
#Use one of the built-in roles: Storage File Data SMB Share Reader, Storage File Data SMB Share Contributor, Storage File Data SMB Share Elevated Contributor
#Constrain the scope to the target file share
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$fileShareName"
#Assign the custom role to the target identity with the specified scope.
New-AzRoleAssignment -ObjectId $ObjectIDGroupUser -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope

#Step 5
#  Run the code below to test the connection and mount the share
$connectTestResult = Test-NetConnection -ComputerName "$StorageAccountName.file.core.windows.net" -Port 445
if ($connectTestResult.TcpTestSucceeded)
{
  net use T: "\\$StorageAccountName.file.core.windows.net\$fileShareName" /user:Azure\$StorageAccountName $StorageAccountKey
} 
else 
{
  Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN,   Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
}

#Step 6 Directory and NTFS
New-Item -Path $DirectoryID -ItemType Directory

#Set the NTFS Right
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /inheritance:d
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Creator Owner"
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant 'CREATOR OWNER:(OI)(CI)(IO)(M)'
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Authenticated Users" 
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Builtin\Users"
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant $domainName\"WVD-Users":M
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant $domainName\"WVD-Admin":F



#Step 7 FSLogix Variables

$LocalAVDpath = "c:\temp\avd"
$FSLogixURI  = "https://aka.ms/fslogix_download"
$FSInstaller = "FSLogixAppsSetup.zip"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$connectionString = '\\' + $StorageAccountName + '.file.core.windows.net\userprofiles'


#create share name for fslogix
# $shareName = $StorageAccountName+'.file.core.windows.net'

#Step 7 Test/Create Temp Directory

if((Test-Path c:\temp) -eq $false) {
    Add-Content -LiteralPath C:\New-AVDSessionHost.log "Create C:\temp Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating temp directory"
    New-Item -Path c:\temp -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\New-AVDSessionHost.log "C:\temp Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "temp directory already exists"
}
if((Test-Path $LocalAVDpath) -eq $false) {
    Add-Content -LiteralPath C:\New-AVDSessionHost.log "Create C:\temp\AVD Directory"
    Write-Host `
        -ForegroundColor Cyan `
        -BackgroundColor Black `
        "creating c:\temp\AVD directory"
    New-Item -Path $LocalAVDpath -ItemType Directory
}
else {
    Add-Content -LiteralPath C:\New-AVDSessionHost.log "C:\temp\AVD Already Exists"
    Write-Host `
        -ForegroundColor Yellow `
        -BackgroundColor Black `
        "c:\temp\AVD directory already exists"
}
New-Item -Path c:\ -Name New-AVDSessionHost.log -ItemType File
Add-Content `
-LiteralPath C:\New-AVDSessionHost.log `
"
ProfilePath       = $connectionString
"

#Step 7    Download AVD Componants    

Add-Content -LiteralPath C:\New-AVDSessionHost.log "Downloading FSLogix"
Invoke-WebRequest -Uri $FSLogixURI -OutFile "$LocalAVDpath\$FSInstaller"

#Step 8    Prep for WVD Install  

Add-Content -LiteralPath C:\New-AVDSessionHost.log "Unzip FSLogix"
Expand-Archive `
    -LiteralPath "C:\temp\AVD\$FSInstaller" `
    -DestinationPath "$LocalAVDpath\FSLogix" `
    -Force `
    -Verbose
cd $LocalAVDpath 
Add-Content -LiteralPath C:\New-AVDSessionHost.log "UnZip FXLogix Complete"

#Step 9    FSLogix Install

Add-Content -LiteralPath C:\New-AVDSessionHost.log "Installing FSLogix"
$fslogix_deploy_status = Start-Process `
    -FilePath "$LocalAVDpath\FSLogix\x64\Release\FSLogixAppsSetup.exe" `
    -ArgumentList "/install /quiet" `
    -Wait `
    -Passthru

#Step 9    FSLogix Local Group Policy available

$SourcePathAdml = "$LocalAVDpath\FSLogix\fslogix.adml"
$SourcePathAdmx = "$LocalAVDpath\FSLogix\fslogix.admx"

Move-item –path $SourcePathAdml –destination C:\Windows\PolicyDefinitions\en-US
Move-item –path $SourcePathAdmx –destination C:\Windows\PolicyDefinitions

#Step 10    FSLogix User Profile Settings

Add-Content -LiteralPath C:\New-AVDSessionHost.log "Configure FSLogix Profile Settings"
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


#Step 11    Add Defender Exclusions for FSLogix

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

#Step 13    FslogixTeamsExclusions

$xmllocation= "\\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory"

#Directory Creation for Teams Exclusion
$DirectoryID= "T:\Teams"
$Directory= "Teams"
New-Item -Path $DirectoryID -ItemType Directory

#Download the Xmlredirection
$xmllocation= "\\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory"
$xmlurl= "https://raw.githubusercontent.com/Zuldajri/AVD/main/redirections.xml"
$connectionString2= "\\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory"

Invoke-WebRequest -Uri $xmlurl -OutFile $xmllocation

#Fslogix regedit configuration
Push-Location 
Set-Location HKLM:\SOFTWARE\

New-ItemProperty `
    -Path HKLM:\Software\FSLogix\Profiles `
    -Name "RedirXMLSourceFolder" `
    -Value $connectionString2 `
    -PropertyType MultiString `
    -Force 




#Step 14    Teams installation

if ($installTeams -eq 'true'){

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

if ($useAVDOptimizer -eq 'true'){
#Step 15    WVD Optimization


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
    New-Item -Path C:\Optimize\ -Name install.log -ItemType File -Force
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Verbose
    add-content c:\Optimize\install.log "Starting Optimizations"  
    & C:\Optimize\Virtual-Desktop-Optimization-Tool-main\Win10_VirtualDesktop_Optimize.ps1 -Optimizations $Optimizations -AcceptEULA -Verbose

}


if ($useScalingPlan -eq 'true'){
    #Step 16    AVD Autoscale

    if (!(Get-AzRoleDefinition -Name "AVD Autoscale")) {
        Write-Host "Role does not exist, creating."
        $role = Get-AzRoleDefinition -Name "Contributor"
        $role.Id = $null
        $role.Name = "AVD Autoscale"
        $role.Description = "Used for AVD Scaling."
        $role.IsCustom = $true
        $role.Actions.RemoveRange(0,$role.Actions.Count)
        $role.Actions.Add("Microsoft.Insights/eventtypes/values/read")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/deallocate/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/restart/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/powerOff/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/start/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/write")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/write")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/delete")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/sendMessage/action")       
        $role.AssignableScopes.Clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        New-AzRoleDefinition -Role $role
        Get-AzRoleDefinition -Name "AVD Autoscale"
    }
    else { 
        Write-Host "Role exists"
        $role=Get-AzRoleDefinition -Name "AVD Autoscale"
        $role.Actions.RemoveRange(0,$role.Actions.Count)
        $role.Actions.Add("Microsoft.Insights/eventtypes/values/read")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/deallocate/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/restart/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/powerOff/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/start/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/write")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/write")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/delete")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/read")
        $role.Actions.Add("Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/sendMessage/action")    
        $role.AssignableScopes.Clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        Set-AzRoleDefinition -Role $role;
    }

    $avdSP = Get-AzADServicePrincipal | Where-Object {$_.DisplayName -eq "Windows Virtual Desktop"} | Where-Object {$_.ServicePrincipalNames -contains "https://mrs-Prod.ame.gbl/mrs-RDInfra-prod"}
    New-AzRoleAssignment -ObjectId $avdSP.Id -RoleDefinitionName "AVD Autoscale" -scope "/subscriptions/$SubscriptionId"
    
}