---
layout: post
title: ACSC BSides IR Challenge 2021 - Setup
author: shanna
categories: CTF
image: assets/images/CTF.png
tags: ACSC-Challenge-2021
toc: true
---
Last Updated: 9 June 2022.

I was lucky enough to get to <a target="_blank" href="https://www.bsidesau.com.au/">BSides Canberra</a> in 2021, but I did not have time on the day(s) to compete in the IR challenge. Generously. the team at the ACSC have provided the challenge in its entirety and I have been working my way through the challenges and will write up each of the different sections on how I solved the challenge and what tools I used. 

This will all be using open source or free to use tools. It could be a slow process as part of this has me working on Autopsy plugins and updating them.

The challenge can be downloaded directly from the ACSC <a href="https://www.cyber.gov.au/acsc/view-all-content/news/acsc-cyber-security-challenge">here</a> along with all the details you need to get going. Big thanks to the ACSC for putting this together and sharing the content.

## Setup
So I could pretend to play along I setup an instance of ctfd locally in docker for windows. This step is not necessary as we have the answers already, but was a bit of fun for playing along.

<ol>
    <li>https://hub.docker.com/r/ctfd/ctfd</li>
    <li>Ran "docker run -p 8000:8000 -it ctfd/ctfd:3.3.1-release" to download the image locally, this was the version that worked for me when I imported the config.</li>
    <li>Imported the provided ctfd_config.zip to my instance.</li>
</ol>

   ![Local CTFd setup]({{site.baseurl}}/assets/images/posts/../../../../assets/images/posts/ACSC_Challenge_2021-Setup01.png)

## Disk Forensics
### Autopsy
> <a href="https://www.autopsy.com/">Autopsy®</a> is the premier end-to-end open source digital forensics platform. Built by Basis Technology with the core features you expect in commercial forensic tools, Autopsy is a fast, thorough, and efficient hard drive investigation solution that evolves with your needs.

I chose Autopsy to run the artefacts through along with some chosen python parsers to demonstrate the capabilities. You can get by in the challenge using artefact parsing tools and log tools, however I wanted to also work on updating some Autopsy plugins and decided to run the artefacts through Autopsy too and have validation for my findings.

Full Autopsy setup and configuration is available <a href="/tools/2022/05/02/Autopsy.html">here</a>.

## Log Review
### Splunk
Splunk is an extremely popular and powerful enterprise data platform. I chose Splunk for the log analysis as there is a free version for non commercial use and learning and gaining skills with Splunk is extremely beneficial for security practitioners. You can get <a target="_blank" href="https://www.splunk.com/en_us/download/get-started-with-your-free-trial.html">Splunk Enterprise on a free trial license</a>.

## Memory Forensics
### 1. Volatility 3
><a target="_blank" href="https://github.com/volatilityfoundation/volatility3">Volatility</a> is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer visibility into the runtime state of the system.

Most of the tools that I use run natively on Windows, but for those maybe function better in Linux I'm leaning more towards WSL2 than a Ubuntu VM. I followed this <a target="_blank" href="https://www.youtube.com/watch?v=rwTWZ7Q5i_w">video by 13Cubed</a> to install Volatility3 and use within WSL2.

**An overview of the process:**
<ol>
<li>Install WSL2: <a target="_blank" href="https://docs.microsoft.com/en-us/windows/wsl/install">https://docs.microsoft.com/en-us/windows/wsl/install</a></li>
<li>From a command prompt within WSL I used the volatility wheel file to download and install the latest version of volatility3: 
    <br><code>python3 -m pip install volatility3-2.0.0-py3-none-any.whl</code></li>
    <ul>
    <li>https://github.com/volatilityfoundation/volatility3/releases</li>
    <li>https://pip.pypa.io/en/latest/user_guide/installing-from-wheels</li>
    </ul>
<li>The binary <code>vol</code> was then available in <code>.local/bin/</code> from the installation directory.</li>
</ol>

### 2. TrufflePig Nexus
> <a target="_blank" href="https://trufflepig-forensics.com/en/product">Nexus</a> analyses Windows memory images fast and reliably with an intuitive Web-UI. It gives a comprehensive overview of artifacts, IoCs and their context which allows for an efficient triage. Trufflepig Nexus was built by practitioners to make memory forensics more efficient and easier accessible to a broader audience.

I came across Trufflepig Forensics on Twitter and wanted to try out and compare the results in memory forensic challenges to Volatility so that I have my validation process, but also try out the GUI front end to make life a little easier.
<ol>
    <li>Download the trial version from https://trufflepig-forensics.com/</li>
    <li>Run the install wizard and setup.</li>
</ol>

## Artefact Parsing

Not everything can be down with touch button forensics, actually most things need to be verified by a multitude of tools, so having the ability to parse artefacts on their own is critical to making sure that you are getting the correct answers to your questions from the evidence.

### 1. EZTools
> These open source <a target=_blank href="https://ericzimmerman.github.io/#!index.md">digital forensics tools</a> can be used in a wide variety of investigations including cross validation of tools, providing insight into technical details not exposed by other tools, and more. Over the years, Eric has written and continually improve over a dozen digital forensics tools that investigators all over the world use and rely upon daily.


Eric Zimmerman provides a PowerShell script to download and catalogue the versions of the tools on your system. Use this script to install and update the EZTools. Eric puts a lot of work into these tools for minimal return, please consider sponsoring his project on Github.

```
    Git clone https://github.com/EricZimmerman/Get-ZimmermanTools
    cd .\Get-ZimmermanTools\
    .\Get-ZimmermanTools.ps1
```

![EZTools script]({{site.baseurl}}/assets/images/posts/EZTools-setup.png)

#### * MFTECmd.exe

When you open the CSV, you will need to set the format for the date/time columns. I set the format for columns T -> AA as `yyyy-mm-dd hh:mm:ss.000`.
<br>NOTE: ensuring that you have the milliseconds represented will stop any rounding which will change your answers.




## Excel Incident Timeline and Tracker
Most organisations use some kind of tracking spreadsheet during investigations. The <a target="_blank" href="https://www.crowdstrike.com/blog/crowdstrike-releases-digital-forensics-and-incident-response-tracker/">CrowdStrike Incident Response Tracker</a> is a convenient spreadsheet that includes sections to document indicators of compromise, affected accounts, compromised systems and a timeline of significant events. CrowdStrike Services released their tracker spreadsheet to assist the Digital Forensics and Incident Response (DFIR) community during incident response investigations.

Of course, feel free to use or create your own.

## Evidence & artefact parsing overview.
If you wanted to get a head start on adding the artefacts to Autopsy and parsing before getting stuck in, the following table outlines what I parsed with what from which systems.

<table class="table table-striped table-sm small w-auto">
  <caption class="figure-caption text-center">Table: System evidence parsing</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col">System</th>
      <th scope="col">MFT</th>
      <th scope="col">Eventlogs</th>
      <th scope="col">IIS Logs</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row"><kbd>dmz-webpub</kbd></th>
      <td>MFTECmd.exe</td>
      <td><b>Autopsy ParseEvtx plugin</b><br>- Application/Security/System<br>- Microsoft-Windows-Windows Defender%4Operational.evtx<br>- DFS Replication.evtx</td>
      <td>Splunk</td>
    </tr>
    <tr>
      <th scope="row"><kbd>corp-webdev</kbd></th>
      <td>MFTECmd.exe</td>
      <td><b>Autopsy ParseEvtx plugin</b><br>- Application/Security/System<br>- Microsoft-Windows-Windows Defender%4Operational.evtx<br>- Microsoft-Windows-SmbClient%4Connectivity.evtx<br>- Microsoft-Windows-SmbClient%4Security.evtx<br>- DFS Replication.evtx</td>
      <td></td>
    </tr>
    <tr>
      <th scope="row"><kbd>corp-dc</kbd></th>
      <td>MFTECmd.exe</td>
      <td>Autopsy ParseEvtx plugin<br>Application/Security/System</td>
      <td></td>
    </tr>
    <tr>
      <th scope="row"><kbd>corp-file</kbd></th>
      <td>MFTECmd.exe</td>
      <td>Autopsy ParseEvtx plugin<br>Application/Security/System<br>Microsoft-Windows-SmbClient%4Security.evtx</td>
      <td></td>
    </tr>
  </tbody>
</table>