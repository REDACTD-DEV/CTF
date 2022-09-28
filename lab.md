# Deploy VMs
```posh
$VMNames = @(‘DC1’,’WinServer’,’WinClient’)
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
        Path = "E:\ISO\WINSERVER.ISO"
    }
    if($VMName -eq "WinClient") {$Params['Path'] = "E:\ISO\Windows.iso"}
    if($VMName -eq "pfSense") {$Params['Path'] = "E:\ISO\pfSense.iso"}
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
## Inital configuration
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
Install-ADDSForest -DomainName ad.contoso.com -DomainNetBIOSName AD -InstallDNS
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
Add-DhcpServerInDC -DnsName dhcp.ad.contoso.com

#Notify Server Manager that DCHP installation is complete, since it doesn't do this automatically
$Params = @{
    Path = "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12"
    Name = "ConfigurationState"
    Value = "2"
}
Set-ItemProperty @Params

#Configure DHCP Scope
Add-DhcpServerv4Scope -name "Corpnet" -StartRange 192.168.10.50 -EndRange 192.168.10.254 -SubnetMask 255.255.255.0 -State Active

#Exclude address range
Add-DhcpServerv4ExclusionRange -ScopeID 192.168.10.0 -StartRange 192.168.10.1 -EndRange 192.168.10.49

#Specify default gateway 
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.10.1 -ScopeID 192.168.10.0 -ComputerName dhcp.ad.contoso.com

#Specify default DNS server
Set-DhcpServerv4OptionValue -DnsDomain ad.contoso.com -DnsServer 192.168.10.10

#Set a DHCP reservation
Set-DhcpServerv4Reservation -ComputerName "dc1.ad.contoso.com" -IPAddress 192.168.10.11 -ScopeID 192.168.10.0 -Description "WSUS" -Name "wsus.ad.contoso.com"
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

#New domain user
$Params = @{
    Name = "John.Smith"
    AccountPassword = (Read-Host -AsSecureString "Enter Password")
    Enabled = $true
    ChangePasswordAtLogon = $true
    DisplayName = "John Smith"
    Company = "Contoso"
    Department = "Information Technology"
    Path = “OU=Employees,OU=Users,OU=Contoso,DC=ad,DC=contoso,DC=com”
}
New-ADUser @Params
#Will have issues logging in through Hyper-V Enhanced Session Mode if not in this group
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "John.Smith"

#Add Company SGs and add members to it
New-ADGroup -Name "All-Staff" -SamAccountName "All-Staff" -GroupCategory Security -GroupScope Global -DisplayName "All-Staff" -Path "OU=SecurityGroups,OU=Groups,OU=Contoso,DC=ad,DC=contoso,DC=com" -Description "Members of this group are employees of Contoso"
Add-ADGroupMember -Identity "All-Staff" -Members "John.Smith"
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
	OUPath = "OU=Workstations,OU=Devices,OU=Contoso,DC=ad,DC=contoso,DC=com"
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

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress = "192.168.10.13"
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
