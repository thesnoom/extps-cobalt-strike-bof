## Extended Process List (ps with search) (64-bit only)

Added search functionality for process listing.

- Credits to @odzhan, Alfie Champion (@ajpc500), SysWhispers, InlineWhispers etc. 

## Compile

```
make
```

## Usage

Aggressor script included with the following commands:
extps
extps proc/user
extps proc user

e.g: extps explorer snoom
e.g: extps snoom
e.g: extps onedrive admin

> NOTE: BOF is for 64-bit use only.

## Example
beacon> extps explorer
[*] Extended process list (@thesnoom)
[+] host called home, sent: 8650 bytes
[+] received output:
- Searching for proc/user explorer
[+] received output:
PID    PPID   Name                           Arch  Session  User
----   ----   ----                           ----  -------  ----
5688   3360   explorer.exe                   x64   1        DESKTOP-G69JOUU\snoom

beacon> extps host snoom
[*] Extended process list (@thesnoom)
[+] host called home, sent: 8651 bytes
[+] received output:
- Searching for host under user snoom
[+] received output:
PID    PPID   Name                           Arch  Session  User
----   ----   ----                           ----  -------  ----
2020   2404   sihost.exe                     x64   1        DESKTOP-G69JOUU\snoom
1904   676    svchost.exe                    x64   1        DESKTOP-G69JOUU\snoom
4088   676    svchost.exe                    x64   1        DESKTOP-G69JOUU\snoom
5132   1708   taskhostw.exe                  x64   1        DESKTOP-G69JOUU\snoom
6368   676    svchost.exe                    x64   1        DESKTOP-G69JOUU\snoom
6656   844    StartMenuExperienceHost.exe    x64   1        DESKTOP-G69JOUU\snoom
8984   676    svchost.exe                    x64   1        DESKTOP-G69JOUU\snoom
7384   844    ApplicationFrameHost.exe       x64   1        DESKTOP-G69JOUU\snoom
744    844    ShellExperienceHost.exe        x64   1        DESKTOP-G69JOUU\snoom
8908   844    dllhost.exe                    x64   1        DESKTOP-G69JOUU\snoom
6288   844    SecurityHealthHost.exe         x64   1        DESKTOP-G69JOUU\snoom

beacon> extps SERVICE
[*] Extended process list (@thesnoom)
[+] host called home, sent: 8649 bytes
[+] received output:
- Searching for proc/user service
[+] received output:
PID    PPID   Name                           Arch  Session  User
----   ----   ----                           ----  -------  ----
8808   676    svchost.exe                    x64   0        NT AUTHORITY\LOCAL SERVICE
2188   1824   audiodg.exe                    x64   0        NT AUTHORITY\LOCAL SERVICE
2336   676    SecurityHealthService.exe      x64   0        NT AUTHORITY\SYSTEM
4568   5688   vm3dservice.exe                x64   1        DESKTOP-G69JOUU\snoom
7364   676    NisSrv.exe                     x64   0        NT AUTHORITY\LOCAL SERVICE
5188   676    svchost.exe                    x64   0        NT AUTHORITY\NETWORK SERVICE
