---
layout: post
title: ACSC BSides IR Challenge 2021 - 04 - Privilege Escalation
author: shanna
categories: CTF
image: assets/images/CTF.png
tags: ACSC-Challenge-2021
toc: true
---
Once the attacker has established themselves on the network, they will look to gain additional privileges such as administrator, or admin like accounts. The questions in this section are focus on `corp-webdev.alien.local`.

To complete this section I have used the following tools:
* EZ Tools - MFTECmd.exe, MFTExplorer.exe
* Autopsy - ParseEVTX Python Ingest Module.

> <a href="https://attack.mitre.org/tactics/TA0004/">TA004</a> - **Privilege Escalation** consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities.These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.

## 4 - Privilege Escalation
So the actor was aware that sample 2 was replicated onto CORP-WEBDEV, giving them access further into the network. What would they have done next?

### PE-1
<h5>It looks like the actor ran some more reconnaissance commands and, once again, forgot to clean up after themselves. What time (UTC) was the file containing the command's output created?</h5>
* Back to the MFT output and looking around we see the following file that looks suspect and something like it could be the output of a tool:
  * ParentPath: .\inetpub\wwwroot\alien
  * FileName: fulldir.txt
  * Timestamp: 2021-04-01 03:08:14.592

<h5>Flag: 2021-04-01 03:08:14</h5>

### M-2
<h5>What time (UTC) was the fulldir.txt file created on the dmz-webpub server?</h5>
* Back to the MFT output on dmz-webpub:
  * ParentPath: .\inetpub\wwwroot\alien
  * FileName: fulldir.txt
  * Timestamp: 2021-04-01 03:08:14.592
* Exactly the same timestamp
<h5>Flag: 2021-04-01 03:08:14</h5>

### PE-2
<h5>What user account was the actor running these commands as?</h5>
1. I'm going to add the artefact folder to Autopsy and run the ParseEVTX plugin.
   
   ![Specify a new host name]({{site.baseurl}}/assets/images/posts/PE-2-1.png)

2. Select the data source type as "Logical Files".
3. Browse to the folder "C" and progress.
   
   ![Specify a new host name]({{site.baseurl}}/assets/images/posts/PE-2-2.png)

4. When you get to the configure ingest window, "deselect All" and then scroll down to "ParseEvtx, and select Security, System and Application in the configuration window and click next and finish and wait for the parser to finish.
   
   ![Specify a new host name]({{site.baseurl}}/assets/images/posts/PE-2-3.png)

5. Once the parser has completed, we'll see the Windows Event Logs in the Data Artifacts Tree on the left. Select that branch and we can now view the parsed eventlogs.
6. We know the timestamp, so we can check the event logs at that time. Just prior to 03:08 there is an entry in the Security eventlog, Event ID 4799 - "A security-enabled local group membership was enumerated". The information in the log show us that the user was IIS APPPOOL and that the command they ran was net1.exe

   ![Specify a new host name]({{site.baseurl}}/assets/images/posts/PE-2-4.png)

<h5>Flag: IIS APPPOOL\alien</h5>

### M-3
<h5>What command did the actor run at 2021-04-01 03:25:44?</h5>
From the screenshot above we can see they ran net1.exe, but that's not the answer they are looking for. EventID 4799 is "A security-enabled local group membership was enumerated". Googling usage of net1.exe you can see the likely command that the attacker ran.

<p>From the event information we can see the Group name and group domain.</p>
<h5>Flag: net localgroup Administrators</h5>

### PE-3
<h5>The actor needed legitimate credentials with higher privilege to continue their attack. What account did they use which had higher privileges?</h5>
We'll want to take a look at what users were logged onto the system.<a href="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624">4624: An account was successfully logged on</a>

Still reviewing the Security event log in Autopsy, we can see the next account used to login (EventID 4624) was "alien_db"
![Autopsy > Windows Event Logs Screenshot](Assets\2022-03-26-04-36-26.png)
We can see more details about this account under the "OS Accounts" link on the left
![Autopsy > OS Account Screenshot](Assets\2022-03-26-04-37-12.png)

<h5>Flag: alien_db</h5>

### M-4
<h5>ALIEN are concerned about the actor using this account - it's an account only used by DotNetNuke to communicate with the supporting database. Potentially the credentials were hard-coded somewhere! Which file could the actor have possibly rooted this password out from?</h5>
Reviewing the MFT will give us an idea of what files were available in the folder, I use "MFTExplorer.exe" as its a bit easier to navigate in the tree structure than reviewing the excel output we already have, but either works.
![Screenshot from MFT Explorer](Assets\2022-02-06-03-55-24.png)

Googled "dotnetnuke+db password" - https://www.dnnsoftware.com/forums/threadid/381245/scope/posts/how-do-i-find-my-database-password

```
<connectionStrings>
      <add
      name="SiteSqlServer"
      connectionString="Server=vista;Database=Demo;uid=someuser;pwd=somepwdr;"
      providerName="System.Data.SqlClient" />
  </connectionStrings>
  ```
<h5>Flag: web.config</h5>

### PE-4
<h5>What time (UTC) did the actor first use this account to continue with their malicious tasks?</h5>
* Looking at corp-webdev-mft-output, just prior to the alien_db account logging on there is a Task created "Windows NUpdate" - looks suspect
* Because of this I'll go and look at the Task Scheduler event log.
  * Microsoft-Windows-TaskScheduler%4Operational.evtx

<h5>Flag: 2021-04-01 03:29:23</h5>

### PE-5
<h5>Continuing to flex there new credentials, the actor then started a process. What was the PID of this first process?</h5>
* Staying with the Task scheduler logs if we go down the actions we come across EventID 129 - Created Task Process:
  
  `Task Scheduler launch task "\Windows NUPdate" , instance "c:\sysinternals\procdump.exe"  with process ID 5372.`
![](Assets\2022-03-26-05-41-48.png)

* Looking at the task itself in "F:\ACSC\ACSC_IR_Challenge_2021\artefacts\corp-webdev.alien.local\C\Windows\System32\Tasks"

```
<Exec>
      <Command>c:\sysinternals\procdump.exe</Command>
      <Arguments>-accepteula -ma lsass.exe c:\inetpuub\wwwroot\alien\lsass.dmp</Arguments>
    </Exec>
```

<h5>Flag: 5372</h5>

### PE-6
<h5>What time (UTC) was the output of this process created on disk?</h5>

* From the previous question we can see the output file is c:\inetpuub\wwwroot\alien\lsass.dmp. 
* Checking the MFT Out put to determine the created date and time.
  ![](Assets\2022-04-01-06-15-23.png)

<h5>Flag: 2021-04-01 03:35:00</h5>