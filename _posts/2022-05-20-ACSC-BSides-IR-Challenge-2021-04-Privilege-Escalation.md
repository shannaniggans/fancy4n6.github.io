---
layout: post
title: ACSC BSides IR Challenge 2021 - 04 - Privilege Escalation
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

## 4 - Privilege Escalation
>So the actor was aware that sample 2 was replicated onto CORP-WEBDEV, giving them access further into the network. What would they have done next?

Once the attacker has established themselves on the network, they will look to gain additional privileges such as administrator, or admin like accounts. The questions in this section are focus on `corp-webdev.alien.local`.

To complete this section I have used the following tools:
* EZ Tools - MFTECmd.exe, MFTExplorer.exe
* Autopsy - ParseEVTX Python Ingest Module.

**Note: See <a target="_blank" href="{{ site.baseurl }}/ACSC-BSides-IR-Challenge-2021-Setup/" target="_blank">this page </a>for tool set up and explanations.**

> <a target="_blank" href="https://attack.mitre.org/tactics/TA0004/">TA004</a> - **Privilege Escalation** consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities.These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.

### PE-1
<h5>It looks like the actor ran some more reconnaissance commands and, once again, forgot to clean up after themselves. What time (UTC) was the file containing the command's output created?</h5>
If we go back to the MFT output for `corp-webdev` and look around we see the following file that looks suspect and something like it could be the output of a tool:
  * ParentPath: .\inetpub\wwwroot\alien
  * FileName: fulldir.txt
  * Timestamp: 2021-04-01 03:08:14.592

You need to just eyeball the timeline and the locations a little but and get to know what looks odd and might be out of place.

<h5>Flag: 2021-04-01 03:08:14</h5>

### M-2
<h5>What time (UTC) was the fulldir.txt file created on the dmz-webpub server?</h5>
Back to the MFT output on `dmz-webpub` and we're looking for the same file and location:
  * ParentPath: .\inetpub\wwwroot\alien
  * FileName: fulldir.txt
  * Timestamp: 2021-04-01 03:08:14.592

It is exactly the same timestamp as `corp-webdev`.
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
We'll want to take a look at what users were logged onto the system so we will want to look for event ID <a target="_blank" href="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624">4624: An account was successfully logged on.</a> To demonstrate additional Autopsy plugins, I'll use the python plugin <a target="_blank" href="https://github.com/markmckinnon/Autopsy-Plugins/tree/master/Process_EVTX_By_EventID">Process_EVTX_By_EventID</a>. Ensure you enter in the EventID into the field before checking the box next to "Other".

   ![ParseEvtxByEventID]({{site.baseurl}}/assets/images/posts/PE-3-1.png)

1. Check out the results in the Data Artifacts tree on the left.
2. We can see the next account used to login (EventID 4624) was "alien_db".

   ![EventID 4624]({{site.baseurl}}/assets/images/posts/PE-3-2.png)

<h5>Flag: alien_db</h5>

### M-4
<h5>ALIEN are concerned about the actor using this account - it's an account only used by DotNetNuke to communicate with the supporting database. Potentially the credentials were hard-coded somewhere! Which file could the actor have possibly rooted this password out from?</h5>
Reviewing the MFT will give us an idea of what files were available in the folder, I use EZ Tools "MFTExplorer.exe" as its a bit easier to navigate in the tree structure than reviewing the excel output we already have, but either works.

   ![Load the MFT into MFTExplorer]({{site.baseurl}}/assets/images/posts/PE-M-4-1.png)

**Note: This will probably take a fairly decent amount of time to load up.**

   ![Load the MFT into MFTExplorer]({{site.baseurl}}/assets/images/posts/PE-M-4-2.png)

I then Googled "dotnetnuke+db password" to see if i can get an idea of where the password might be stored and found this - <a href="https://www.dnnsoftware.com/forums/threadid/381245/scope/posts/how-do-i-find-my-database-password">"how do I find my database password"</a>.
  * *The databasename, userid, and password will be found in the < connectionStrings > section of the site's **web.config** file located in the root of the site's filesystem. It is not accessible from the portal or host settings or from the file manager. It is not necessary to keep the same database password. When moving the site don't forget to update BOTH connection strings with the new information. The second connection string is under the < appSettings > section of web.config and is the node with key="SiteSqlServer".*

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

Often in CTFs they will add clues to the questions as to what they are looking for, and in this instance it is the word "tasks". To find that I looked at the
corp-webdev MFT output around the time of the alien_db account logging on. 

Just prior to this there is a task created at 2021-04-01 03:29:23: "Windows NUpdate" - looks suspect.

   ![Suspicious task created]({{site.baseurl}}/assets/images/posts/PE-4.png)

<h5>Flag: 2021-04-01 03:29:23</h5>

### PE-5
<h5>Continuing to flex their new credentials, the actor then started a process. What was the PID of this first process?</h5>

So we saw that there was a t least one malicious schedule task created by the attacker. So I'll want to:
1. look at the Task Scheduler event log - Microsoft-Windows-TaskScheduler%4Operational.evtx
2. Review the tasks in "corp-webdev.alien.local\C\Windows\System32\Tasks”.

We can review the EventLogs in Autopsy, or simply open the event log file in Event Viewer and we'll see that there are 3859 events in total in the log file.

Sorting on Date and Time and finding the corresponding event to 2021-04-01 03:29:23:
* 1/04/2021 3:29:23 AM - Task registered - `User "alien_db"  registered Task Scheduler task "\Windows NUPdate"`
* 1/04/2021 3:30:34 AM - Launch request queued - `Task Scheduler queued instance "{9c83b591-e787-449c-92f3-3e87b1301577}"  of task "\Windows NUPdate".`
* 1/04/2021 3:30:35 AM - Created Task Process - `Task Scheduler launch task "\Windows NUPdate" , instance "c:\sysinternals\procdump.exe"  with process ID 5372.`

<h5>Flag: 5372</h5>

### PE-6
<h5>What time (UTC) was the output of this process created on disk?</h5>

Looking at the task itself in notepad - "F:\ACSC\ACSC_IR_Challenge_2021\artefacts\corp-webdev.alien.local\C\Windows\System32\Tasks" we can see a lot of information about the task in XML format, including the execution information. 

```
<Exec>
      <Command>c:\sysinternals\procdump.exe</Command>
      <Arguments>-accepteula -ma lsass.exe c:\inetpuub\wwwroot\alien\lsass.dmp</Arguments>
    </Exec>
```

We can easily see that the output file was named `lsass.dmp` and was configured to write to the c:\inetpuub\wwwroot\alien\ directory.

The easiest way to check this is to go back to our MFT output and find the created date and time stamp: 2021-04-01 03:35:00

<h5>Flag: 2021-04-01 03:35:00</h5>

**Note: You may have noticed another task called Windows YUpdate in the task folder as well... I wonder when we need to look at that?**

   ![Windows tasks]({{site.baseurl}}/assets/images/posts/PE-6.png)