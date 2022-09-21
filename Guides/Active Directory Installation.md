## Inital configuration on all servers
```posh
#Rename the server
Rename-Computer -NewName DC1

#Restart the server
Restart-Computer -Force

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress         = "192.168.10.10"
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
Set-DNSClientServerAddress @Params
```

## Install AD DS
```posh
#Install AD DS server role
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

#Configure server as a domain controller
Install-ADDSForest -DomainName ad.contoso.com -DomainNetBIOSName AD -InstallDNS
```

## DNS server configuration
```posh
Set-DnsServerForwarder -IPAddress "1.1.1.1" -PassThru
```

## Basic AD Configuration
```posh
#Create OU's
#Base OU
New-ADOrganizationalUnit “Contoso” –path “DC=ad,DC=contoso,DC=com”
#Devices
New-ADOrganizationalUnit “Devices” –path “OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “Servers” –path “OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “Workstations” –path “OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com”
#Users
New-ADOrganizationalUnit “Users” –path “OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “Admins” –path “OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “Employees” –path “OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
#Groups
New-ADOrganizationalUnit “Groups” –path “OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “SecurityGroups” –path “OU=Groups,OU=Contoso,DC=ad,DC=contoso,DC=com”
New-ADOrganizationalUnit “DistributionLists” –path “OU=Groups,OU=Contoso,DC=ad,DC=contoso,DC=com”
```

## Install and configure DHCP server
```posh
#Install DCHP server role
Install-WindowsFeature DHCP -IncludeManagementTools

#Add required DHCP security groups on server and restart service
netsh dhcp add securitygroups
Restart-Service dhcpserver

#Authorize DHCP Server in AD
Add-DhcpServerInDC -DnsName ad.contoso.com

#Notify Server Manager that DCHP installation is complete, since it doesn't do this automatically
$Params = @{
    Path  = "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12"
    Name  = "ConfigurationState"
    Value = "2"
}
Set-ItemProperty @Params

#Configure DHCP Scope
Add-DhcpServerv4Scope -name "Corpnet" -StartRange 192.168.10.50 -EndRange 192.168.10.254 -SubnetMask 255.255.255.0 -State Active

#Exclude address range
Add-DhcpServerv4ExclusionRange -ScopeID 192.168.10.0 -StartRange 192.168.10.1 -EndRange 192.168.10.49

#Specify default gateway 
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.10.1 -ScopeID 192.168.10.0 -ComputerName DC1.ad.contoso.com

#Specify default DNS server
Set-DhcpServerv4OptionValue -DnsDomain ad.contoso.com -DnsServer 192.168.10.10

#Set a DHCP reservation
Set-DhcpServerv4Reservation -ComputerName "dc1.ad.contoso.com" -IPAddress 192.168.10.11 -ScopeID 192.168.10.0 -Description "WSUS" -Name "wsus.ad.contoso.com"
```

## Create users
```posh
#New admin user
$Params = @{
    Name                  = "Admin-John.Smith"
    AccountPassword       = (Read-Host -AsSecureString "Enter Password:")
    Enabled               = $true
    ChangePasswordAtLogon = $true
    DisplayName           = "John Smith - Admin"
    Path                  = “OU=Admins,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params
#Add admin to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "Admin-John.Smith"

#New domain user
$Params = @{
    Name                  = "John.Smith"
    AccountPassword       = (Read-Host -AsSecureString "Enter Password:")
    Enabled               = $true
    ChangePasswordAtLogon = $true
    DisplayName           = "John Smith"
    Company               = "Contoso"
    Department            = "Information Technology"
    Path                  = “OU=Employees,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params
#Will have issues logging in through Hyper-V Enhanced Session Mode if not in this group
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "John.Smith"

#Add Company SGs and add members to it
New-ADGroup -Name "All-Staff" -SamAccountName "All-Staff" -GroupCategory Security -GroupScope Global -DisplayName "All-Staff" -Path "CN=SecurityGroups,OU=Groups,OU=Contoso,DC=ad,DC=contoso,DC=com" -Description "Members of this group are employees of Contoso"
Add-ADGroupMember -Identity "All-Staff" -Members "John.Smith"

```

## Join a computer to an existing domain
```posh
#Run from an elevated powershell console
$Params = @{
	DomainName	=	"ad.contoso.com"
	OUPath		=	"OU=Workstations,OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com"
	Credential	=	"ad.contoso.com\Administrator"
	NewName		=	(Get-WmiObject Win32_BIOS).SerialNumber #Sets Name as Serial
	Force		=	$true
	Restart		=	$true
}
Add-Computer @Params
```

## Install RSAT
```posh
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
```

## Create file share
```posh
#Bring data disk online
Initialize-Disk -Number 1
#Partition and format
New-Partition -DiskNumber 1 -UseMaximumSize | Format-Volume -FileSystem "NTFS" -NewFileSystemLabel "Data"
#Set drive letter 
Set-Partition -DiskNumber 1 -PartionNumver 2 -NewDriveLetter D

#Create share folder
New-Item "D:\Data\NetworkShare" -Type Directory

$Params = @{
    Name                  = "NetworkShare"
    Path                  = "D:\Data\NetworkShare"
    FullAccess            = "Domain Admins"
    ReadAccess            = "Domain Users"
    FolderEnumerationMode = "Unrestricted"
}
New-SmbShare @Params
```

## Drive Mapping
```posh
#Create GPO
$gpoOuObj=new-gpo -name "All Staff Mapped Drive"

#Link GPO to domain
new-gplink -Guid $gpoOuObj.Id.Guid -target "DC=ad,DC=contoso,DC=com"

#Get GUID and make it upper case
$guid = $gpoOuObj.Id.Guid.ToUpper()

#Create a folder that the GP MMC snap-in normally would
$path="\\ad.contoso.com\SYSVOL\ad.contoso.com\Policies\{$guid}\User\Preferences\Drives"
New-Item -Path $path -type Directory | Out-Null

#Variables that would normally be set in the Drive Mapping dialog box
$Letter     = "M"
$Label      = "NetworkShare"
$SharePath  = "\\ad.contoso.com\NetworkShare"
$ILT        = "AD\All-Staff"
$SID        = (Get-ADGroup "All-Staff").SID.Value

#Date needs to be inserted into the XML
$Date       = Get-Date -Format "yyyy-MM-dd hh:mm:ss"

#A Guid needs to be inserted into the XML - This can be completely random 
$RandomGuid = New-Guid
$RandomGuid = $RandomGuid.Guid.ToUpper()

#The XML
$data       = @"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
	<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" bypassErrors="1" uid="{$RandomGuid}" changed="$Date" image="2" status="${Letter}:" name="${Letter}:">
		<Properties letter="$Letter" useLetter="1" persistent="1" label="$Label" path="$SharePath" userName="" allDrives="SHOW" thisDrive="SHOW" action="U"/>
		<Filters>
      <FilterGroup bool="AND" not="0" name="$ILT" sid="$SID" userContext="1" primaryGroup="0" localGroup="0"/>
    </Filters>
	</Drive>
</Drives>
"@
#Write XML
$data | out-file $path\drives.xml -Encoding "utf8"

#Edit AD Attribute "gPCUserExtensionNames" since the GP MMC snap-in normally would 
$ExtensionNames = "[{00000000-0000-0000-0000-000000000000}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}][{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]"
Set-ADObject -Identity "CN={$guid},CN=Policies,CN=System,DC=ad,DC=contoso,DC=com" -Add @{gPCUserExtensionNames=$ExtensionNames}

#A versionNumber of 0 means that clients won't get the policy since it hasn't changed
#Edit something random (and easy) so it increments the versionNumber properly
#This one removes the computer icon from the desktop.
@Params = @{
    Name      = "All Staff Mapped Drive"
    Key       = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum"
    Type      = DWORD
    ValueName = "{645FF040-5081-101B-9F08-00AA002F954E}"
    Value     = 1
}
set-GPRegistryValue @Params
```

