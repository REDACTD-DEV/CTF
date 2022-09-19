## Inital configuration on all servers
```posh
#Rename the server
Rename-Computer -NewName DC1

#Restart the server
Restart-Computer

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
New-ADGroup “Contosot” -path ‘OU=Groups,OU=Rome,OU=IT,dc=bobcares,DC=com’
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
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.10.10 -ScopeID 192.168.10.0 -ComputerName DC1.ad.contoso.com

#Specify default DNS server
Set-DhcpServerv4OptionValue -DnsDomain ad.contoso.com -DnsServer 192.168.10.10
```

## Create users
```posh
#New admin user
$Params = @{
    Name                  = "Admin-John.Smith"
    AccountPassword       = (Read-Host -AsSecureString "ChangeM3!")
    Enabled               = $true
    ChangePasswordAtLogon = $true
    DisplayName           = "John Smith - Admin"
    Path                  = “OU=Admins,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params

#New domain user
$Params = @{
    Name                  = "John.Smith"
    AccountPassword       = (Read-Host -AsSecureString "ChangeM3!")
    Enabled               = $true
    ChangePasswordAtLogon = $true
    DisplayName           = "John Smith"
    Company               = "Contoso"
    Department            = "Information Technology"
    Path                  = “OU=Employees,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params

```

## Join a computer to an existing domain
```posh
$Params @{
	DomainName	=	"ad.contoso.com"
	OUPath		=	"OU=Workstations,OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com"
	Credential	=	"ad.contoso.com\Administrator"
	NewName		=	Get-WmiObject Win32_BIOS | Select SerialNumber #Sets Name as Serial
	Force		=	$true
	Restart		=	$true
}
Add-Computer @Params
```

## Create file share
```posh
#Create share folder
New-Item "D:\Data\NetworkShare" -Type Directory

$Params = @{
    Name                  = "NetworkShare"
    EncryptData           = $true
    Path                  = "D:\Data\NetworkShare"
    FullAccess            = "Domain Admins"
    ReadAccess            = "Domain Users"
    FolderEnumerationMode = "AccessBased"
}
New-SmbShare @Params
```

## Drive Mapping
```posh
#Create GPO to map the drive
$Params @{
    Name    = "TestGPO"
    Comment = "This is a test GPO."  
}
New-GPO @Params
```
