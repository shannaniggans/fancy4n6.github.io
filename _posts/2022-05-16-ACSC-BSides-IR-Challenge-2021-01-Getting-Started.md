---
layout: post
title: ACSC BSides IR Challenge 2021 - 01 - Getting Started
author: shanna
categories: CTF
image: assets/images/CTF.png
tags: ACSC-Challenge-2021
toc: true
---
#### Post series
In April 2021 the ACSC hosted an IR challenge at BSides Canberra. I am writing up a blog post for each of the different sections of the challenge including the tools set up. The complete listing of all the parts I've written up can be found <a target="_blank" href="{{ site.baseurl }}/tags#ACSC-Challenge-2021">here.</a>

The challenge can be downloaded <a href="https://www.cyber.gov.au/acsc/view-all-content/news/acsc-cyber-security-challenge">here</a> along with all the details you need to get going. 
<p>-----</p>

## 1 - Getting Started

>The Australian Logic and Interstellar Exploration Network (ALIEN) needs your help! An unknown cyber actor has blackmailed ALIEN claiming that they will release their research unless they are paid a hefty sum. ALIEN believe that the information must have been stolen through a cyber intrusion, and have enlisted your help to work alongside the ACSC to investigate what has happened.

This part of the CTF is just about looking at the artefacts and data received, counting out the number of hosts and creating a checksum of a memory image. For this section I will use the following tools:
* FTK Imager
* PowerShell
* Volatility
* TrufflePig Nexus

### GS-0
* Press submit on this one to continue.

### GS-1
<h5>How many hosts have we received data from?</h5>

* Easy one, just count the number of zip files provided as they named by host.

<h5>Flag: 9</h5>

### GS-2
<h5>What is the MD5 hash of the memory image provided?</h5>

#### GS-2-1 PowerShell
* Because we are dealing with a RAW image file, we can use PowerShell to calculate the hash of the file itself.

  ```Get-FileHash memory.raw -Algorithm MD5 | Format-List```

#### GS-2-2 FTK Imager
We cant always use PowerShell to get an image if there is compression or added metadata (such as an E01 or an AFF file).

1. In FTK Imager, add `memory.raw` as an evidence item.
   ![FTK select source]({{site.baseurl}}/assets/images/posts/FTK-select-source.png)
2. Click next and browse to where you have memory.raw decompressed. You'll then have the memory image in the evidence tree section of FTK Imager.
3. Right click on memory.raw and select "verify Drive/Image"
   ![FTK verify image]({{site.baseurl}}/assets/images/posts/FTK-verify-drive.png)
4. Allow the verification process to complete, the results will be displayed on screen.   
   ![FTK verify image]({{site.baseurl}}/assets/images/posts/image-verification-results.png)

<h5>Flag: 20b25f76cc1839c2e7759a69a82bf664</h5>

### GS-3
<h5>What time was this image taken?</h5>

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

#### GS-3-2 TrufflePig Nexus
1. Create a project in Nexus and import the memory.raw image.
2. From the menu on the left choose "metaInfo"
3. Scroll down to "SystemTime"
  ![MetaInfo in Nexus]({{site.baseurl}}/assets/images/posts/GS-3-2-nexus.png)

<h5>Flag: 2021-04-06 01:56:57</h5>

### GS-4
<h5>What website management platform are ALIEN using for their public facing website?</h5>

* Just looked at the web log files and googled the cs_uri_stem `/Install/InstallWizard.aspx __VIEWSTATE=&culture=en-US&executeinstall` to see what came back:
  * <a href="https://www.exploit-db.com/raw/39777">https://www.exploit-db.com/raw/39777</a><br>
  * <a href="https://msadiqm.blogspot.com/2017/11/dotnetnuke-070400-administration.html">https://msadiqm.blogspot.com/2017/11/dotnetnuke-070400-administration.html</a>

<h5>Flag: DotNetNuke</h5>