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
  [string] $hostpoolName,
  [string] $enableOnConnect,
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
Install-Module -Name Az -RequiredVersion 6.6.0 -force -AllowClobber
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


if ($domainType -eq 'AD'){
    if ($hostname -like '*host1'){
        #Step 3 domain join the file share

        New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb1
        $Token = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey | Where-Object {$_.KeyName -eq "kerb1"}).Value
        $stoUri = ([uri](Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).PrimaryEndpoints.File).Host

        $scriptblock= {
            $ADDomainName = (Get-ADDomain -Identity $Using:domainName).Name
            $NetBiosDomainName = (Get-ADDomain -Identity $Using:domainName).NetBIOSName
            $ForestName = (Get-ADDomain -Identity $Using:domainName).Forest
            $DomainGuid = (Get-ADDomain -Identity $Using:domainName).ObjectGuid.Guid
            $DomainSid = (Get-ADDomain -Identity $Using:domainName).DomainSID.Value
            New-ADComputer -Name $Using:StorageAccountName -AccountPassword (ConvertTo-SecureString -AsPlainText $Using:Token -Force)
            Set-ADComputer -Identity $Using:StorageAccountName -ServicePrincipalNames @{Add="cifs/$Using:stoUri"}
            $StorAccountSid = (Get-ADComputer -Identity $Using:StorageAccountName).SID.Value
        }

        $session = New-PSSession -cn $adComputerName -Credential $mycreds 
	    Invoke-Command -Session $session -ScriptBlock $scriptblock 
        $ADDomainName = Invoke-Command -Session $session -ScriptBlock { $ADDomainName }
        $NetBiosDomainName = Invoke-Command -Session $session -ScriptBlock { $NetBiosDomainName }
        $ForestName = Invoke-Command -Session $session -ScriptBlock { $ForestName }
        $DomainGuid = Invoke-Command -Session $session -ScriptBlock { $DomainGuid }
        $DomainSid = Invoke-Command -Session $session -ScriptBlock { $DomainSid }
        $StorAccountSid = Invoke-Command -Session $session -ScriptBlock { $StorAccountSid }
	    Remove-PSSession -VMName $adComputerName
    
        Import-Module Az -Force

        #Connection Needed for Azure 
        $azurePassword = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($aadClientId , $azurePassword)
        Connect-AzAccount -Credential $psCred -TenantId $TenantId  -ServicePrincipal
        Select-AzSubscription -SubscriptionId $SubscriptionId   

        ## Provide Set-AzStorageAccount with all appropriate GUIDs and SIDs
        ## along with the AD domain it should be a part of
        Set-AzStorageAccount `
            -ResourceGroupName $ResourceGroupName `
            -Name $StorageAccountName `
            -EnableActiveDirectoryDomainServicesForFile $true `
            -ActiveDirectoryDomainName $ADDomainName `
            -ActiveDirectoryNetBiosDomainName $NetBiosDomainName `
            -ActiveDirectoryForestName $ForestName `
            -ActiveDirectoryDomainGuid $DomainGuid `
            -ActiveDirectoryDomainsid $DomainSid `
            -ActiveDirectoryAzureStorageSid $StorAccountSid

        #Confirm the feature is enabled
        $storageaccount = Get-AzStorageAccount `
            -ResourceGroupName $ResourceGroupName `
            -Name $StorageAccountName

        $storageAccount.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
        $storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
    }
}


if (!($hostname -like '*host1')){sleep 120}

Import-Module Az -Force

#Connection Needed for Azure 
$azurePassword = ConvertTo-SecureString $aadClientSecret -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($aadClientId , $azurePassword)
Connect-AzAccount -Credential $psCred -TenantId $TenantId  -ServicePrincipal
Select-AzSubscription -SubscriptionId $SubscriptionId

if ($hostname -like '*host1'){
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
}

if (!($hostname -like '*host1')){sleep 30}

#Step 5
#Add the Admin Rights to the Admin Group and User Group
$RBACA1 = Get-AzRoleDefinition $RBACAdmin1
$RBACA2 = Get-AzRoleDefinition $RBACAdmin2
$RBACA3 = Get-AzRoleDefinition $RBACAdmin3
$RBACA4 = Get-AzRoleDefinition $RBACAdmin4
$RBACA5 = Get-AzRoleDefinition $RBACAdmin5
$RBACA6 = Get-AzRoleDefinition $RBACAdmin6
$RBACU1 = Get-AzRoleDefinition $RBACUser1

#Use the built-in roles:
#Constrain the scope to the target Azure Sub
$scopeRBAC = "/subscriptions/$SubscriptionId"
#Assign the custom role to the target identity with the specified scope.
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA1.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA1.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA2.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA2.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA3.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA3.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA4.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA4.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA5.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA5.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA6.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACA6.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACU1.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupAdmin -RoleDefinitionName $RBACU1.Name -Scope $scopeRBAC}
if (!(Get-AzRoleAssignment -ObjectId $ObjectIDGroupUser -RoleDefinitionName $RBACU1.Name -scope $scopeRBAC)){New-AzRoleAssignment -ObjectId $ObjectIDGroupUser -RoleDefinitionName $RBACU1.Name -Scope $scopeRBAC}


#Step 6
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

#Step 7 Directory and NTFS
if((Test-Path $DirectoryID) -eq $false) { New-Item -Path $DirectoryID -ItemType Directory }

#Set the NTFS Right
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /inheritance:d
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Creator Owner"
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant 'CREATOR OWNER:(OI)(CI)(IO)(M)'
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Authenticated Users" 
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /remove "Builtin\Users"
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant $domainName\"AVD-Users":M
icacls \\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory /grant $domainName\"AVD-Admin":F



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

#Step 8    Download AVD Componants    

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

$xmllocation= "\\$StorageAccountName.file.core.windows.net\$fileShareName\$Directory"

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

#Directory Creation for Teams Exclusion
$DirectoryIDT= "T:\Teams"
$DirectoryT= "Teams"

if((Test-Path $DirectoryIDT) -eq $false) { New-Item -Path $DirectoryIDT -ItemType Directory }

#Download the Xmlredirection
$localpath2 = "C:\temp\AVD\redirection.xml"
$xmlurl= "https://raw.githubusercontent.com/Zuldajri/AVD/main/redirections.xml"
Invoke-WebRequest -Uri $xmlurl -OutFile $localpath2
sleep 10


if ((Test-Path T:\Teams\redirections.xml) -eq $false){ mv C:\temp\AVD\redirection.xml T:\Teams\redirections.xml }

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

#Step 16    Enable Time Zone Redirection
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection  /t REG_DWORD /d 1 /f

if ($useAVDOptimizer -eq 'true'){
#Step 17    WVD Optimization


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

if ($enableOnConnect -eq 'true'){
    #Step 18    Start Virtual Machine on Connect
    if (!(Get-AzRoleDefinition -Name "Start VM on connect (Custom)")) {
        Write-Host "Role does not exist, creating."
        $role = Get-AzRoleDefinition -Name "Contributor"
        $role.Id = $null
        $role.Name = "Start VM on connect (Custom)"
        $role.Description = "Used for Start VM on connect."
        $role.IsCustom = $true
        $role.Actions.RemoveRange(0,$role.Actions.Count)
        $role.Actions.Add("Microsoft.Compute/virtualMachines/start/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/*/read")     
        $role.AssignableScopes.Clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        New-AzRoleDefinition -Role $role
        Get-AzRoleDefinition -Name "Start VM on connect (Custom)"
    }
    else { 
        Write-Host "Role exists"
        $role=Get-AzRoleDefinition -Name "Start VM on connect (Custom)"
        $role.Actions.RemoveRange(0,$role.Actions.Count)
        $role.Actions.Add("Microsoft.Compute/virtualMachines/start/action")
        $role.Actions.Add("Microsoft.Compute/virtualMachines/*/read")     
        $role.AssignableScopes.Clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        Set-AzRoleDefinition -Role $role
    }

    $avdSP1 = Get-AzADServicePrincipal | Where-Object {$_.DisplayName -eq "Windows Virtual Desktop"} | Where-Object {$_.ServicePrincipalNames -contains "https://mrs-Prod.ame.gbl/mrs-RDInfra-prod"}
    if (!(Get-AzRoleAssignment -ObjectId $avdSP1.Id -RoleDefinitionName "Start VM on connect (Custom)" -scope "/subscriptions/$SubscriptionId")){New-AzRoleAssignment -ObjectId $avdSP1.Id -RoleDefinitionName "Start VM on connect (Custom)" -scope "/subscriptions/$SubscriptionId"}
    $avdSP2 = Get-AzADServicePrincipal | Where-Object {$_.DisplayName -eq "Windows Virtual Desktop"} | Where-Object {$_.ServicePrincipalNames -contains "https://www.wvd.microsoft.com"}
    if (!(Get-AzRoleAssignment -ObjectId $avdSP2.Id -RoleDefinitionName "Start VM on connect (Custom)" -scope "/subscriptions/$SubscriptionId")){New-AzRoleAssignment -ObjectId $avdSP2.Id -RoleDefinitionName "Start VM on connect (Custom)" -scope "/subscriptions/$SubscriptionId"}

    Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $hostpoolName -StartVMOnConnect:$true
}

if ($useScalingPlan -eq 'true'){
    #Step 19    AVD Autoscale

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
        Set-AzRoleDefinition -Role $role
    }

    $avdSP1 = Get-AzADServicePrincipal | Where-Object {$_.DisplayName -eq "Windows Virtual Desktop"} | Where-Object {$_.ServicePrincipalNames -contains "https://mrs-Prod.ame.gbl/mrs-RDInfra-prod"}
    if (!(Get-AzRoleAssignment -ObjectId $avdSP1.Id -RoleDefinitionName "AVD Autoscale" -scope "/subscriptions/$SubscriptionId")){New-AzRoleAssignment -ObjectId $avdSP1.Id -RoleDefinitionName "AVD Autoscale" -scope "/subscriptions/$SubscriptionId"}
    $avdSP2 = Get-AzADServicePrincipal | Where-Object {$_.DisplayName -eq "Windows Virtual Desktop"} | Where-Object {$_.ServicePrincipalNames -contains "https://www.wvd.microsoft.com"}
    if (!(Get-AzRoleAssignment -ObjectId $avdSP2.Id -RoleDefinitionName "AVD Autoscale" -scope "/subscriptions/$SubscriptionId")){New-AzRoleAssignment -ObjectId $avdSP2.Id -RoleDefinitionName "AVD Autoscale" -scope "/subscriptions/$SubscriptionId"}
    
}
