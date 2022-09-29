# 20742 Lab
|    VM   |   IP Address  |
| ------- | ------------- |
| `DC1`   | 192.168.10.10 |
| `Client`| 192.168.10.50 |

# Deploy VMs
```posh
$VMNames = @(‘DC-01’,’CL-01’)
Foreach ($VMName in $VMNames) {
    $Params = @{
        Name = $VMName
        MemoryStartupBytes = 1GB
        Path = "E:\$VMName"
        Generation = 2
        SwitchName = "Private Virtual Switch"
    }
    New-VM @Params

    #Edit VM
    $Params = @{
        Name = $VMName
        ProcessorCount = 4
        DynamicMemory = $true
        MemoryMinimumBytes = 1GB
        MemoryMaximumBytes = 4GB
    }
    Set-VM @Params

    #Specify CPU settings
    $Params = @{
        VMName = $VMName
        Count = 8
        Maximum = 100
        RelativeWeight = 100
    }
    Set-VMProcessor @Params

    #Add Installer ISO
    $Params = @{
        VMName = $VMName
        Path = "E:\ISO\WINDOWS-SERVER-22.iso"
    }
    if($VMName -eq "CL-01") {$Params['Path'] = "E:\ISO\Windows-22H1.iso"}
    Add-VMDvdDrive @Params

    #Create OS Drive
    $Params = @{
        Path = "E:\$VMName\Virtual Hard Disks\$VMName-OS.vhdx"
        SizeBytes = 60GB
        Dynamic = $true
    }
    New-VHD @Params

    #Create Data Drive
    $Params = @{
        Path = "E:\$VMName\Virtual Hard Disks\$VMName-Data.vhdx"
        SizeBytes = 500GB
        Dynamic = $true
    }
    New-VHD @Params

    #Add OS Drive to VM
    $Params = @{
        VMName = $VMName
        Path = "E:\$VMName\Virtual Hard Disks\$VMName-OS.vhdx"
    }
    Add-VMHardDiskDrive @Params

    #Add Data Drive to VM
    $Params = @{
        VMName = $VMName
        Path = "E:\$VMName\Virtual Hard Disks\$VMName-Data.vhdx"
    }
    Add-VMHardDiskDrive @Params

    #Set boot priority
    Set-VMFirmware -VMName $VMName -BootOrder $(Get-VMDvdDrive -VMName $VMName), $(Get-VMHardDiskDrive -VMName $VMName | where Path -match "OS"), $(Get-VMHardDiskDrive -VMName $VMName | where Path -match "Data")

    Start-VM -Name $VMName
}
```

# DC1
## Initial configuration
```posh
#Rename the server
Rename-Computer -NewName DC1

#Restart the server
Restart-Computer -Force

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress = "192.168.10.10"
  DefaultGateway = "192.168.10.1"
  PrefixLength = "24"
  InterfaceIndex = (Get-NetAdapter).InterfaceIndex
}
New-NetIPAddress @Params

#Configure DNS Settings
$Params = @{
  ServerAddresses = "192.168.10.10"
  InterfaceIndex = (Get-NetAdapter).InterfaceIndex
}
Set-DNSClientServerAddress @Params
```

## Install AD DS
```posh
#Install AD DS server role
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

#Configure server as a domain controller
Install-ADDSForest -DomainName adf.com -DomainNetBIOSName ADF -InstallDNS
```

## DNS server configuration
```posh
Set-DnsServerForwarder -IPAddress "1.1.1.1" -PassThru
```

## Install and configure DHCP server
```posh
#Install DCHP server role
Install-WindowsFeature DHCP -IncludeManagementTools

#Add required DHCP security groups on server and restart service
netsh dhcp add securitygroups
Restart-Service dhcpserver

#Authorize DHCP Server in AD
Add-DhcpServerInDC -DnsName adf.com

#Notify Server Manager that DCHP installation is complete, since it doesn't do this automatically
$Params = @{
    Path = "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12"
    Name = "ConfigurationState"
    Value = "2"
}
Set-ItemProperty @Params

#Configure DHCP Scope
Add-DhcpServerv4Scope -name "Corpnet" -StartRange 192.168.10.21 -EndRange 192.168.10.254 -SubnetMask 255.255.255.0 -State Active

#Exclude address range
Add-DhcpServerv4ExclusionRange -ScopeID 192.168.10.0 -StartRange 192.168.10.1 -EndRange 192.168.10.20

#Specify default gateway 
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.10.1 -ScopeID 192.168.10.0 -ComputerName adf.com

#Specify default DNS server
Set-DhcpServerv4OptionValue -DnsDomain ad.contoso.com -DnsServer 192.168.10.10

#Set DHCP reservations
Set-DhcpServerv4Reservation -ComputerName "wsus.adf.com" -IPAddress 192.168.10.11 -ScopeID 192.168.10.0 -Description "WSUS" -Name "wsus.adf.com"
Set-DhcpServerv4Reservation -ComputerName "fs01.adf.com" -IPAddress 192.168.10.12 -ScopeID 192.168.10.0 -Description "FS01" -Name "fs01.adf.com"
Set-DhcpServerv4Reservation -ComputerName "fs02.adf.com" -IPAddress 192.168.10.13 -ScopeID 192.168.10.0 -Description "fs02" -Name "fs02.adf.com"
```

## Basic AD Configuration
```posh
#Create OU's
#Base OU
New-ADOrganizationalUnit “ADF” –path “DC=adf,DC=com”
#Devices
New-ADOrganizationalUnit “Devices” –path “OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Servers” –path “OU=Devices,OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Workstations” –path “OU=Devices,OU=ADF,DC=adf,DC=com”
#Users
New-ADOrganizationalUnit “Users” –path “OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Admins” –path “OU=Users,OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Navy” –path “OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Army” –path “OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “Air Force” –path “OU=ADF,DC=adf,DC=com”
#Groups
New-ADOrganizationalUnit “Groups” –path “OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “SecurityGroups” –path “OU=Groups,OU=ADF,DC=adf,DC=com”
New-ADOrganizationalUnit “DistributionLists” –path “OU=Groups,OU=ADF,DC=adf,DC=com”
```

## Create users
```posh
#New admin user
$Params = @{
    Name = "Admin-John.Smith"
    AccountPassword = (Read-Host -AsSecureString "Enter Password")
    Enabled = $true
    ChangePasswordAtLogon = $true
    DisplayName = "John Smith - Admin"
    Path = “OU=Admins,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params
#Add admin to Domain Admins group
Add-ADGroupMember -Identity "Domain Admins" -Members "Admin-John.Smith"

#New domain users
$Params = @{
    Name = "John.Smith"
    AccountPassword = (Read-Host -AsSecureString "Enter Password")
    Enabled = $true
    ChangePasswordAtLogon = $false
    PasswordNeverExpires = $true
    DisplayName = "John Smith"
    Company = "Contoso"
    Department = "Information Technology"
    Path = “OU=Army,OU=ADF,DC=adf,DC=com”
}
New-ADUser @Params

$Params = @{
    Name = "Jane.Doe"
    AccountPassword = (Read-Host -AsSecureString "Enter Password")
    Enabled = $true
    ChangePasswordAtLogon = $false
    PasswordNeverExpires = $true
    DisplayName = "Jane Doe"
    Company = "Contoso"
    Department = "Accounting"
    Path = “OU=Navy,OU=ADF,DC=adf,DC=com”
}
New-ADUser @Params

$Params = @{
    Name = "Jimmy.Neutron"
    AccountPassword = (Read-Host -AsSecureString "Enter Password")
    Enabled = $true
    ChangePasswordAtLogon = $false
    PasswordNeverExpires = $true
    DisplayName = "Jimmy Neutron"
    Company = "Contoso"
    Department = "Sales"
    Path = “OU=Air Force,OU=ADF,DC=adf,DC=com”
}
New-ADUser @Params

#Add Company SGs and add members to it
New-ADGroup -Name "All-Staff" -SamAccountName "All-Staff" -GroupCategory Security -GroupScope Global -DisplayName "All-Staff" -Path "OU=SecurityGroups,OU=Groups,OU=ADF,DC=adf,DC=com" -Description "Members of this group are employees of Contoso"
Add-ADGroupMember -Identity "All-Staff" -Members "John.Smith","Jane.Doe","Jimmy.Neutron"
```

# WinClient
## Join a computer to an existing domain
```posh
#Set computer name as Serial
Rename-Computer -NewName (Get-WmiObject Win32_BIOS).SerialNumber

#Restart
Restart-Computer -Force

#Run from an elevated powershell console
$Params = @{
	DomainName = "ad.contoso.com"
	OUPath = "OU=Workstations,OU=Devices,OU=ADF,DC=adf,DC=com"
	Credential = "ad.contoso.com\Administrator"
	Force = $true
	Restart = $true
}
Add-Computer @Params
```

## Install RSAT
```posh
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
```

## Initial Configuration
```posh
#Rename the server
Rename-Computer -NewName FS01

#Restart computer
Restart-Computer -Force

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress = "192.168.10.11"
  DefaultGateway = "192.168.10.1"
  PrefixLength = "24"
  InterfaceIndex = (Get-NetAdapter).InterfaceIndex
}
New-NetIPAddress @Params

#Configure DNS Settings
$Params = @{
  ServerAddresses = "192.168.10.10"
  InterfaceIndex = (Get-NetAdapter).InterfaceIndex
}
Set-DNSClientServerAddress @Params
```

## Join server to an existing domain
```posh
$Params = @{
	DomainName = "ad.contoso.com"
	OUPath = "OU=Servers,OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com"
	Credential = "ad.contoso.com\Administrator"
	Force =	$true
	Restart = $true
}
Add-Computer @Params
```
