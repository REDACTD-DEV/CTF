![Windows Event Logs](https://assets.tryhackme.com/additional/win-event-logs/wel-room-banner2.png)
# Windows Event Logs
## Event Viewer
For the questions below, use Event Viewer to analyze Microsoft-Windows-PowerShell/Operational log.

What is the Event ID for the first event?
```posh
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Select-Object -Last 1 | select Id
```
``` 40961```


Filter on Event ID 4104. What was the 2nd command executed in the PowerShell session?

```posh
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | Select-Object Id, Message | Select-Object -Last 2 | Select-Object -First 1 | fl
```
``` whoami ```


What is the Task Category for Event ID 4104?

```posh
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | Select-Object TaskDisplayName | Select-Object -First 1
```

``` Execute a Remote Command ```


For the question below, use Event Viewer to analyze the Windows PowerShell log.

What is the Task Category for Event ID 800?

```posh
Get-WinEvent -LogName "Windows PowerShell" | Where-Object Id -eq 800 | Select-Object TaskDisplayName | Select-Object -First 1
```

``` Pipeline Execution Details ```

## wevtutil.exe
How many log names are in the machine? 

``` Answer format: **** ```


What is the definition for the query-events command?

``` Answer format: **** ```
What option would you use to provide a path to a log file?

``` Answer format: **** ```
What is the VALUE for /q?
``` Answer format: **** ```
The questions below are based on this command: wevtutil qe Application /c:3 /rd:true /f:text

No answer needed
What is the log name?

``` Answer format: **** ```
What is the /rd option for?

``` Answer format: **** ```
What is the /c option for?

