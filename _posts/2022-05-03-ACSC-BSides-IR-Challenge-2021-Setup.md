---
layout: post
title: ACSC BSides IR Challenge 2021 - Setup
author: shanna
categories: CTF
image: assets/images/CTF.png
tags: ACSC-Challenge-2021
toc: true
---
I was lucky enough to get to BSides Canberra in 2021, but I did not have time on the day(s) to compete on the IR challenge. But the team at the ACSC have provided the challenge in its entirety and I have been working my way through the challenges and will write up each of the different sections on how I solved the challenge and what tools I used. 

Essentially this will all be using open source tools. It could be a slow process as part of this has me working on Autopsy plugins and updating them.

The challenge can be downloaded <a href="https://www.cyber.gov.au/acsc/view-all-content/news/acsc-cyber-security-challenge">here</a> along with all the details you need to get going. Big thanks to the ACSC for putting this together and sharing the content.

## Setup
So I could pretend to play along I setup an instance of ctfd locally in docker for windows.

<ol>
    <li>https://hub.docker.com/r/ctfd/ctfd</li>
    <li>Ran "docker run -p 8000:8000 -it ctfd/ctfd:3.3.1-release" to download the image locally, this was the version that worked for me when I imported the config.</li>
    <li>Imported the provided ctfd_config.zip to my instance.</li>
</ol>

   ![Local CTFd setup]({{site.baseurl}}/assets/images/posts/../../../../assets/images/posts/ACSC_Challenge_2021-Setup01.png)

## Disk Forensics
### Autopsy

Full Autopsy setup and configuration available <a href="/tools/2022/05/02/Autopsy.html">here</a>


## Log Review
### Splunk

## Memory Forensics
### 1. Volatility 3
<ol>
<li>Installing WSL2 - https://docs.microsoft.com/en-us/windows/wsl/install</li>
<li>From a command prompt within WSL I used the volatility wheel file to download and install the latest version of volatility3: 
    `python3 -m pip install volatility3-2.0.0-py3-none-any.whl`</li>
    <ul>
    <li>https://github.com/volatilityfoundation/volatility3/releases</li>
    <li>https://pip.pypa.io/en/latest/user_guide/installing-from-wheels</li>
    </ul>
<li>The binary `vol` was then available in `.local/bin/` from the installation directory</li>
</ol>

### 2. TrufflePig Forensics
<ol>
    <li>Download the trial version from https://trufflepig-forensics.com/</li>
    <li>Run the install wizard and setup.</li>
</ol>

## Artefact Parsing

Not everything can be down with touch button forensics, actually most things need to be verified by a multitude of tools, so having the ability to parse artefacts on their own is critical to making sure that you are getting the correct answers to your questions from the evidence.

### 1. EZTools
Eric Zimmerman provides a PowerShell script to download and catalogue the versions of the tools on your system. Use this script to install and update the EZTools.

```
    Git clone https://github.com/EricZimmerman/Get-ZimmermanTools
    cd .\Get-ZimmermanTools\
    .\Get-ZimmermanTools.ps1
```

![EZTools script]({{site.baseurl}}/assets/images/posts/EZTools-setup.png)

#### * MFTECmd.exe

When you open the CSV, you will need to set the format for the date/time columns. I set the format for columns T -> AA as `yyyy-mm-dd hh:mm:ss.000`.
NOTE: ensuring that you have the milliseconds represented will stop any rounding which will change your answers.




## Excel Incident Timeline and Tracker


https://www.crowdstrike.com/blog/crowdstrike-releases-digital-forensics-and-incident-response-tracker/