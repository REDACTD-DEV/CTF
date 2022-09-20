## Initial Server Configuration

```posh
#Rename the server
Rename-Computer -NewName WSUS

#Restart the server
Restart-Computer -Force

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress         = "192.168.10.11"
  DefaultGateway    = "192.168.10.1"
  PrefixLength      = "24"
  InterfaceIndex    = (Get-NetAdapter).InterfaceIndex
}
New-NetIPAddress @Params

#Configure DNS Settings
$Params = @{
  ServerAddresses   = "192.168.10.10"
  InterfaceIndex    = (Get-NetAdapter).InterfaceIndex
}

## Join server to an existing domain
```posh
$Params = @{
	DomainName	=	"ad.contoso.com"
	OUPath		=	"OU=Servers,OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com"
	Credential	=	"ad.contoso.com\Administrator"
	Force		=	$true
	Restart		=	$true
}
Add-Computer @Params
```

## Setup data disk
```posh
#Bring data disk online
Initialize-Disk -Number 1
#Partition and format
New-Partition -DiskNumber 1 -UseMaximumSize | Format-Volume -FileSystem "NTFS" -NewFileSystemLabel "Data"
#Set drive letter 
Set-Partition -DiskNumber 1 -PartionNumver 2 -NewDriveLetter E
```

## Install WSUS
```posh
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
New-Item "E:\WSUS_Content" -Type Directory
CD "C:\Program Files\Update Services\Tools"
.\wsusutil.exe postinstall CONTENT_DIR=E:\WSUS_Content

#Set WSUS to pull updates from MS
Set-WsusServerSynchronization -SyncFromMU

#Only download English updates
$wsusConfig = (Get-WsusServer).GetConfiguration()
$wsusConfig.AllUpdateLanguagesEnabled = $false
$wsusConfig.SetEnabledUpdateLanguages("en")
$wsusConfig.Save()


# Get WSUS Subscription and perform initial synchronization to get latest categories
$subscription = $wsus.GetSubscription()
$subscription.StartSynchronizationForCategoryOnly()

#Set products to get updates for
Get-WsusProduct | where-Object {
	$_.Product.Title -in (
		'Microsoft Defender Antivirus',
		'Microsoft Defender for Endpoint',
		'Microsoft Edge',
		'Microsoft Online Services Sign-In Assistant',
		'Microsoft Online Services',
		'Office 2016',
		'PowerShell',
		'Visual Studio 2022',
		'Windows - Client, version 21H2 and later, Servicing Drivers',
		'Windows - Client, version 21H2 and later, Upgrade & Servicing Drivers',
		'Windows - Server, version 21H2 and later, Servicing Drivers',
		'Windows - Server, version 21H2 and later, Upgrade & Servicing Drivers',
		'Windows 11',
		'Windows Admin Center',
		'Windows Server 2019',
		'Windows Server Drivers',
		'Windows Server Manager – Windows Server Update Services (WSUS) Dynamic Installer',
		'Windows Server, version 1903 and later',
		'Windows Subsystem for Linux')
}  | Set-WsusProduct

#For some reason the above sets the entire Windows product set, or it's set by default

Get-WsusProduct | where-Object {
    $_.Product.Title -in (
	'Windows'
)
} | Set-WsusProduct -Disable

#Configure synchronization
$subscription.SynchronizeAutomatically = $true

#Sync at midnight
$subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
$subscription.NumberOfSynchronizationsPerDay=1
$subscription.Save()
