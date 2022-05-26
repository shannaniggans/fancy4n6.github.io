---
layout: post
title: ACSC BSides IR Challenge 2021 - 02 - Initial Access
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

## 2 - Initial Access

>ALIEN are adamant that the most likely place for a malicious actor to get into their network is their public web server hosting the main website, and have seen some odd activity recently. They have provided some data from this server in zip **dmz-webpub.alien.local.zip**. We'll start by looking there.

There are 5 questions in this section that are primarily focused on external facing systems and their log files. There are a few options to review the logs provided as part of the zip file, but I opted to set up Splunk and do the challenge using Splunk.

Log parser is another great option to parse IIS logs.

> <a href="https://attack.mitre.org/tactics/TA0001/">TA001</a> - **Initial Access** consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.

### IA-1
<h5>The actor seems to have initially failed to install themselves on the web server. What IP address did their malicious wizardry come from?</h5>
* You can get Splunk Enterprise on a free trial license for non commercial use - https://www.splunk.com/en_us/download/get-started-with-your-free-trial.html which is handy to have for these things and to play and learn Splunk on.
* You can upload a zip file of all the provided IIS log files to Splunk and I created an index for the challenge.

1. Start by removing the local IP of 10.1.0.80 from the results:
   ```
   index="acsc_ir_challenge_2021"
   | sort _time
   | where NOT c_ip="10.1.0.80"
   ```
2. In general, GET requests are what we'll see for normal traffic to a website, so I filtered on POST requests to see what came back:
   ```
	index="acsc_ir_challenge_2021"
	| sort _time
	| where NOT c_ip="10.1.0.80"
	| where cs_method="POST"
   ```
3. Traffic originating from 13.54.35.87 sticks out in the listing with multiple POST requests to /Telerik.Web.UI.WebResource.axd. So ill filter on that IP now:
   ```
   index="acsc_ir_challenge_2021"
   | sort _time
   | where c_ip="13.54.35.87"
   ```
4. There was a clue in the question so the following event was the one related:
	```
	2021-04-01 02:35:41 10.1.0.80 GET /Install/InstallWizard.aspx __VIEWSTATE=&culture=en-US&executeinstall 80 - 13.54.35.87 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:54.0)+Gecko/20100101+Firefox/54.0 - 404 0 0 42
	```
    ![Filter on the known bad IP address]({{site.baseurl}}/assets/images/posts/IA-1-3.png)

Their malicious 'wizardry' that failed (404 status)

<h5>Flag: 13.54.35.87</h5>

# IA-2
<h5>It looks like the actor eventually succeeded in gaining access using a combination of multiple well-documented CVEs. Which of these is the most recent?</h5>

* The first indication in the log files that they were successful in gain access (status 500) is the log entry:
	```
	2021-04-01 02:49:08 10.1.0.80 POST /Telerik.Web.UI.WebResource.axd type=rau 80 - 13.54.35.87 python-urllib3/1.26.2 - 500 0 0 52
	c_ip = 13.54.35.87host = dmz-webpubsource = u_ex210401.logsourcetype = iis
	```
    ![Attacker first successful access]({{site.baseurl}}/assets/images/posts/IA-2.png)

* Googling `/Telerik.Web.UI.WebResource.axd` and CVE makes it pretty clear that there are a few CVEs bouncing about, but they have asked for the most recent. 
* Coincidentally (or not) an <a href="https://www.cyber.gov.au/acsc/view-all-content/advisories/advisory-2020-004-remote-code-execution-vulnerability-being-actively-exploited-vulnerable-versions-telerik-ui-sophisticated-actors">advisory</a> was put out by the ACSC in 2020 that has the interesting details in it.

<h5>Flag: CVE-2019-18935</h5>

* on a side note and maybe for later, the advisory talked about evidence of the exploit in application event logs, so I jumped in to the eventlogs to correlate.
  
   ![Filter on the known bad IP address]({{site.baseurl}}/assets/images/posts/2022-01-21-15-45-20.png)

**IOCs from the advisory**

| Item                           | Info                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Advisories and CVEs            | CVE-2019-18935, ACSC 2020-004 & ACSC 2019-126                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Review web server request logs | `POST /Telerik.Web.UI.WebResource.axd type=rau 443 – 192.0.2.1 - - 500 0 0 457`<br> - These POST requests may be larger in size than legitimate requests due to the malicious actor uploading malicious files for the purposes of uploading a reverse shell binary.                                                                                                                                                                                                                                                                                                     |
| Review Windows event logs      | Event ID: 1309<br> Source: ASP.NET \<version_number\><br>Message: Contains the following strings in addition to other error message content:<br>An unhandled exception has occurred.<br>`Unable to cast object of type ‘System.Configuration.Install.AssemblyInstaller’ to type ‘Telerik.Web.UI.IAsyncUploadConfiguration`<br>Organisations should review the application event logs on vulnerable or previously vulnerable hosts for indications of Telerik exploitation. This analysis can be combined looking for associated HTTP 500 responses as identified above. |

# IA-3
<h5>What was the filename of the first file created by the actor to test that their exploit worked? (We'll refer to this test file as sample 1)</h5>

* Given we are looking for a file created I will parse the MFT and look for files created on the file system that corresponding to the timeline from the IIS log analysis:
  * around 2021-04-01 02:50 UTC
* <a href="/ctf/2022/05/03/ACSC-BSides-IR-Challenge-2021-Setup.html">EZTools - MFTECmd.exe</a> will do the trick to parse the $MFT file provided in the artefacts folder (root of C drive). I'll run this from a PowerShell window.

#### EvtxExplorer - MFTECmd

  ```
  C:\Users\fancy_4n6\Desktop\EZTools\MFTECmd.exe --csv "c:\temp\out" --csvf dmz-webpub-mft-c.csv
  ```
* Open the CSV, you will need to set the format for the date/time columns. I set the format for columns T -> AA as yyyy-mm-dd hh:mm:ss.000.
  * NOTE: ensuring that you have the milliseconds represented will stop any rounding which will change your answers.
* I then set a filter on the top row and sorted by column T "Created0x10"
* Looking at around 2021-04-01, something immediately caught my eye in Column F ".\Windows\Temp and two files 1617245542.475716.dll (2021-04-01 02:52:10) and 1617245455.5314393.dll (2021-04-01 02:50:43) created after we know the attacker was able to successfully exploit the CVE. We are looking for the first file filename.

<h5>Flag: 1617245455.5314393.dll</h5>

This wasn't specifically called out as required for a challenge, but during a normal investigation I'd likely do some OSINT on these files names. The files are no longer on disk, or we don't have copies of that folder, so it will just be based on what I know so far.

| File Name              | Location        | Size   | MD5 | Created Date on C   | Info |
| ---------------------- | --------------- | ------ | --- | ------------------- | ---- |
| 1617245455.5314393.dll | C:\Windows\Temp | 91648  |     | 2021-04-01 02:50:43 |      |
| 1617245542.475716.dll  | C:\Windows\Temp | 118784 |     | 2021-04-01 02:52:10 |      |

It was a long shot and in this instance I came back with nothing from Google + VirusTotal.

# IA-4
<h5>After calling home, the actor finally succeeded in dropping their core tool, sample 2.What time (UTC) was this tool first used?</h5>

From the MFT we know that the attacker dropped some files starting at 2021-04-01 02:50:43 (IA-3), when we look below those entries there are a few more curious entries that look like updates being pushed to the site.

Correlating the logs we can expect that the attacker was able to use their tool via submit.aspx so the correct date time they are after relates to the time in the IIS logs and the attacker action and the first use.

| Date Time           | Artefact | Info                                                                                                                        |
| ------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------- |
| 2021-04-01 02:24:30 | IIS Logs | First time we see 13.54.35.87 in the logs                                                                                   |
| 2021-04-01 02:46:33 | IIS Logs | First time we see 13.54.35.87 POST to /Telerik.Web.UI.WebResource.axd                                                       |
| 2021-04-01 02:50:43 | MFT      | C:\Windows\Temp\1617245455.5314393.dll                                                                                      |
| 2021-04-01 02:52:10 | MFT      | C:\Windows\Temp\1617245542.475716.dll                                                                                       |
| 2021-04-01 02:55:29 | IIS Logs | First time we see 13.54.35.87 GET to /submit.aspx                                                                           |
| 2021-04-01 02:55:30 | MFT      | .\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\App_Web_aa0aecbt.dll          |
| 2021-04-01 02:55:30 | MFT      | .\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\submit.aspx.cdcab7d2.compiled |
| 2021-04-01 02:55:30 | MFT      | .\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\App_Web_aa0aecbt.dll          |

This is where starting to build a timeline is very handy. I usually do this as a dashboard in my excel worksheet for the particular engagement.

   ![Timeline in Excel]({{site.baseurl}}/assets/images/posts/IA-4-timeline.png)

<h5>Flag:2021-04-01 02:55:29</h5>

## Memory and TrufflePig Forensics
Wanted to have a look at network connections and things going on related to this IP address in memory and found the following netconns:
   ![Netconns for the actor IP in Nexus]({{site.baseurl}}/assets/images/posts/IA-nexus.png)

We will be looking at those further I'm sure in subsequent questions.










