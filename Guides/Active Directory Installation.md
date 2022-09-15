## Inital configuration on all servers
```posh
#Rename the server
Rename-Computer -NewName DC1

#Restart the server
Restart-Computer

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
$Params = @{
  IPAddress         = "192.168.1.10"
  DefaultGateway    = "192.168.1.1"
  PrefixLength      = "24"
  InterfaceIndex    = (Get-NetAdapter).InterfaceIndex
}
New-NetIPAddress @Params

#Configure DNS Settings
$Params = @{
  ServerAddresses   = "192.168.1.10"
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
Add-DhcpServerv4Scope -name "Corpnet" -StartRange 192.168.1.50 -EndRange 192.168.1.254 -SubnetMask 255.255.255.0 -State Active

#Exclude address range
Add-DhcpServerv4ExclusionRange -ScopeID 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.49

#Specify default gateway 
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.1.10 -ScopeID 192.168.1.0 -ComputerName DC1.ad.contoso.com

#Specify default DNS server
Set-DhcpServerv4OptionValue -DnsDomain ad.contoso.com -DnsServer 192.168.1.10
```

