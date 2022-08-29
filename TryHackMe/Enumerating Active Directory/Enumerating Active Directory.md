![Enumerating AD](https://assets.tryhackme.com/room-banners/attacking-ad.png)
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


Apart from the Domain Users group, what other group is the aaron.harris account a member of?

```batch
net user aaron.harris /domain
```

``` Internet Access ```


Is the Guest account active?

```batch
net user Guest /domain
```

``` Account active: No ```


How many accounts are a member of the Tier 1 Admins group?

```batch
net group "Tier 1 Admins" /domain
```

``` 7 ```


What is the account lockout duration of the current password policy in minutes?

```batch
net accounts /domain
```

``` Lockout duration (minutes): 30 ```


What is the value of the Title attribute of Beth Nolan (beth.nolan)?

```posh
get-aduser -Identity beth.nolan -Properties title | select title
```

``` Senior ```

What is the value of the DistinguishedName attribute of Annette Manning (annette.manning)?

```posh
get-aduser -Identity annette.manning | select DistinguishedName
```

``` CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com ```

When was the Tier 2 Admins group created?

```posh
Get-ADGroup -Identity "Tier 2 Admins" -Properties Created | select Created
```

``` 2/24/2022 10:04:41 PM ```

What is the value of the SID attribute of the Enterprise Admins group?

```posh
Get-ADGroup -Identity "Enterprise Admins" -Properties SID | select SID
```

``` S-1-5-21-3330634377-1326264276-632209373-519 ```

Which container is used to store deleted AD objects?

```posh
Get-ADDomain | select DeletedObjectsContainer
```

``` CN=Deleted Objects,DC=za,DC=tryhackme,DC=com ```
