## Enumerating Active Directory

```console
root@ip-10-10-211-126:~# nslookup thmdc.za.tryhackme.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	thmdc.za.tryhackme.com
Address: 10.200.58.101
```

``` Your credentials have been generated: Username: elliott.allen Password: Changeme123 ```


How many Computer objects are part of the Servers OU?

```posh
(Get-ADComputer -Filter * | Where-Object DistinguishedName -like "*Servers*").count
```

``` 2 ```


How many Computer objects are part of the Workstations OU?

```posh
#On older versions of PowerShell, if count is 0 or 1, need to manually cast as an array or .count will not work.
@(Get-ADComputer -Filter * | Where-Object DistinguishedName -like "*Workstations*").count
```

``` 1 ```


How many departments (Organisational Units) does this organisation consist of?

```posh
(Get-ADObject -Filter * | Where-Object {($_.objectClass -like "*organizationalUnit*") -and ($_.distinguishedName -like "*,OU=People*")}).count
```

``` 7 ```



How many Admin tiers does this organisation have?

```posh
(Get-ADObject -Filter * | Where-Object {($_.objectClass -like "*organizationalUnit*") -and ($_.distinguishedName -like "*,OU=Admins*")}).count
```

``` 3 ```


What is the value of the flag stored in the description attribute of the t0_tinus.green account?

```posh
Get-ADUser -Properties description -Filter * | Where-Object name -eq t0_tinus.green | select Description
```

``` THM{Enumerating.Via.MMC} ```
