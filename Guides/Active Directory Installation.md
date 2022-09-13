```posh
#Rename the server
Rename-Computer -NewName DC1

#Restart the server
Restart-Computer

#Set IP Address (Change InterfaceIndex param if there's more than one NIC)
New-NetIPAddress –IPAddress 192.168.1.10 -DefaultGateway 192.168.1.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex

#Configure DNS Settings
Set-DNSClientServerAddress –InterfaceIndex (Get-NetAdapter).InterfaceIndex –ServerAddresses 192.168.1.10 

#Install AD DS server role
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools

#Configure server as a domain controller
Install-ADDSForest -DomainName ad.contoso.com -DomainNetBIOSName AD -InstallDNS