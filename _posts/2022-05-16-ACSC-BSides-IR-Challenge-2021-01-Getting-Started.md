---
layout: posts
categories: CTF
title: ACSC BSides IR Challenge 2021 - 01 - Getting Started
date: '2022-05-16 +1000'
last_modified: '2022-05-16 +1000'
---
The Australian Logic and Interstellar Exploration Network (ALIEN) needs your help! An unknown cyber actor has blackmailed ALIEN claiming that they will release their research unless they are paid a hefty sum. ALIEN believe that the information must have been stolen through a cyber intrusion, and have enlisted your help to work alongside the ACSC to investigate what has happened.

## 1 - Getting Started
### GS-0
* Press submit on this one to continue.

### GS-1
<div class="ctfq">How many hosts have we received data from?</div>

* Easy one, just count the number of zip files provided as they named by host.

<div class="flag">Flag: 9</div>

### GS-2
<div class="ctfq">What is the MD5 hash of the memory image provided?</div>

#### GS-2-1 PowerShell
* Because we are dealing with a RAW image file, we can use PowerShell to calculate the hash of the file itself.

  ```Get-FileHash memory.raw -Algorithm MD5 | Format-List```

#### GS-2-2 FTK Imager
* 

<div class="flag">Flag: 20b25f76cc1839c2e7759a69a82bf664</div>

### GS-3
<div class="ctfq">What time was this image taken?</div>

I want to use a few different tools to get the answers and test out some new tools along the way, so I've started here.

#### GS-3-1 Volatility
* <a href="/ctf/2022/05/03/ACSC-BSides-IR-Challenge-2021-Setup.html">Installed Volatility3 in WSL2</a>
* Once Volatility was installed I ran the windows.info plugin to find the answer.
  
  ```./vol -f "/mnt/c/temp/memory.raw" windows.info```
``` 
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf80732ea1f08
Major/Minor     15.17763
MachineType     34404
KeNumberProcessors      2
SystemTime      2021-04-06 01:56:57
NtSystemRoot    C:\Windows
NtProductType   NtProductServer
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Mon Nov 22 08:46:06 2010
```

#### GS-3-2 TrufflePig Forensics
 * Couldn't see where I could find this information in TPF

<div class="flag">Flag: 2021-04-06 01:56:57</div>

### GS-4
<div class="ctfq">What website management platform are ALIEN using for their public facing website?</div>

* Just looked at the web log files and googled the cs_uri_stem `/Install/InstallWizard.aspx __VIEWSTATE=&culture=en-US&executeinstall` to see what came back:
  * <a href="https://www.exploit-db.com/raw/39777">https://www.exploit-db.com/raw/39777</a><br>
  * <a href="https://msadiqm.blogspot.com/2017/11/dotnetnuke-070400-administration.html">https://msadiqm.blogspot.com/2017/11/dotnetnuke-070400-administration.html</a>

<div class="flag">Flag: DotNetNuke</div>