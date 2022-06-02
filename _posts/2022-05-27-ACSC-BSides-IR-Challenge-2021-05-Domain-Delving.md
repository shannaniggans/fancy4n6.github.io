---
layout: post
title: ACSC BSides IR Challenge 2021 - 05 - Domain Delving
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

## 5 - Domain Delving

> Given the output of their process, it looks like the actor was after domain credentials! What could they have done with them?

To begin with we are still looking at `corp-webdev.alien.local` for what the adversary did next. Having gained access and privileged accounts, we'll want to know what their next steps were and see where else they were able to get about the network. There are a few artefacts to review in this one, and a few different ways to do it, scheduled tasks, event logs, file creation and deletion, and some PowerShell to review. In this section you need to think a little bit bigger than the original evidence that we have already parsed or looked at. Pulling apart adversarial scripts and command lines can help tell us loads of the story and then point us to the right next place to look.

This section also has us starting to look at `corp-dc` as we see the adversary expanding their footprint.

Google is your friend, don't expect that you will know all the Windows event log IDs, or potentially every possible attack. Googling some of the clues may point you in the right direction and give you more artefacts or things to look for to verify that's actually what has occurred.

> <a target="_blank" href="https://attack.mitre.org/tactics/TA0008/">TA008</a> - **Lateral Movement** consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.

To complete this section I have used the following tools:
* MFT output spreadsheet
* Autopsy - ParseEVTX Python Ingest Module.

**Note: See <a href="{{ site.baseurl }}/ACSC-BSides-IR-Challenge-2021-Setup/" target="_blank">this page </a>for tool set up and explanations.**

### DD-1
<h5>The actor downloaded a tool, which we’ll call sample 3, to further map the network. What time (UTC) was this tool downloaded? Flag format: yyyy-mm-dd hh:mm:ss</h5>

Using the parsed MFT output we can see the creation of the file "psmap.zip" in the SysInternals folder. Checking under the created column we get our answer.

  ![psmap.zip in the MFT output]({{site.baseurl}}/assets/images/posts/2022-03-26-06-29-15.png)

<h5>Flag: 2021-04-01 04:10:20</h5>

### DD-2
<h5>To facilitate this tool's execution, the actor made a configuration change. What time (UTC) did this occur? Flag format: yyyy-mm-dd hh:mm:ss</h5>

The screenshot from PE-6 shows another scheduled task created - Windows YUpdate. Once again we'll grab the file from "..\ACSC_IR_Challenge_2021\artefacts\corp-webdev.alien.local\C\Windows\System32\Tasks" and open it in notepad to review what was executed.

```
  <RegistrationInfo>
    <Date>2021-04-01T05:10:54</Date>
    <Author>IIS APPPOOL\alien</Author>
    <URI>\Windows YUPdate</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2021-04-01T05:12:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  ---
   <Exec>
      <Command>powershell</Command>
      <Arguments>-inputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "c:\sysinternals"</Arguments>
    </Exec>
```

We'll go back to the Task Scheduler event log - Microsoft-Windows-TaskScheduler%4Operational.evtx to review the chain of events we can see after the registration date of the task (above):
* 1/04/2021 5:10:54 AM - Task registered - `User "alien_db"  updated Task Scheduler task "\Windows YUPdate"`
* 1/04/2021 5:12:00 AM - Task triggered on scheduler - `Task Scheduler launched "{6cf06a5d-da7c-47f2-af45-2eb6eacdf773}"  instance of task "\Windows YUPdate" due to a time trigger condition.`
* 1/04/2021 5:12:00 AM - Created Task Process - `Task Scheduler launch task "\Windows YUPdate" , instance "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE"  with process ID 1312.`
* 1/04/2021 5:12:00 AM - Task Started - `Task Scheduler started "{6cf06a5d-da7c-47f2-af45-2eb6eacdf773}" instance of the "\Windows YUPdate" task for user "CORP-WEBDEV\alien_db".`
* 1/04/2021 5:12:00 AM - Task Completed - `Task Scheduler successfully finished "{6cf06a5d-da7c-47f2-af45-2eb6eacdf773}" instance of the "\Windows YUPdate" task for user "CORP-WEBDEV\alien_db".`

We can also break down the PowerShell command that was set to run:

<table class="table table-striped table-sm">
  <caption class="figure-caption text-center">Table: PowerShell Command Break down</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col">Command</th>
      <th scope="col">Explanation</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row"><code>inputformat none</code></th>
      <td>Describes the format of data sent to PowerShell. Valid values are "Text" (text strings) or "XML" (serialized CLIXML format).</td>
    </tr>
    <tr>
      <th scope="row"><code>NonInteractive</code></th>
      <td>Does not present an interactive prompt to the user.</td>
    </tr>
    <tr>
      <th scope="row"><code>Command Add-MpPreference</code></th>
      <td>Executes the specified commands (and any parameters) as though they were typed at the PowerShell command prompt, and then exits, unless the NoExit parameter is specified.<br>The Add-MpPreference cmdlet modifies settings for Windows Defender. Use this cmdlet to add exclusions for file name extensions, paths, and processes, and to add default actions for high, moderate, and low threats.</td>
    </tr>
    <tr>
      <th scope="row"><code>ExclusionPath "c:\sysinternals"</code></th>
      <td>This command adds the folder C:\sysinternals to the exclusion list. The command disables Windows Defender scheduled and real-time scanning for files in this folder.</td>
      <td></td>
    </tr>
  </tbody>
</table>

Give that the question is looking for a configuration change, the date and time when the schedule task completed and updated the Windows defender configuration would be the likely flag. So we'll look at the defender eventlog - Microsoft-Windows-Windows Defender%4Operational.evtx. I have just reviewed this in notepad, but you could also run ParseEvtx to add this log to the timeline window in Autopsy (and why not add the Task operational log too).

  ![Run ParseEvtx in Autopsy]({{site.baseurl}}/assets/images/posts/DD-2-1.png)

  ![Configuration change identified in Defender logs]({{site.baseurl}}/assets/images/posts/DD-2-2.png)

Building out a timeline of activity can be immensely helpful in identifying any gaps in attacker activity, and also the time frame of the attack. In the screenshot above, its nice to be able to see the task scheduler logs and then the order of events leading up to the configuration change at 05:12:01, which is our flag.

<h5>Flag: 2021-04-01 05:12:01</h5>

### M-5
<h5>What time (UTC) was the scheduled task used for the Defender configuration change first created?</h5>

Can find this in the MFT for the created date and time.
  ![]({{site.baseurl}}/assets/images/posts/2022-04-01-07-54-33.png)

<h5>Flag: 2021-04-01 03:49:01</h5>

### DD-3
<h5>Now with domain credentials, the actor attempted to access other hosts on the network. Which domain account were they using for these connections? Flag format: username</h5>

* We know the lsass was dumped at 03:35:00 to disk, so the attacker would have been able to get the credentials and start lateral movement after this time.
  
  ![Next logon recorded]({{site.baseurl}}/assets/images/posts/DD-3-1.png)

* "4648: A logon was attempted using explicit credentials - 
This event is generated when a process attempts to log on an account by explicitly specifying that account’s credentials.  This most commonly occurs in batch-type configurations such as scheduled tasks, or when using the RUNAS command."

<h5>Flag: dev_agardner</h5>

### DD-4
<h5>What was the hostname of the host that the actor failed to access? Flag format: hostname</h5>

The event log we looked at above (ID:4648) shows us an attempt. At 05:44:26 there is another 4648 event recorded attempting to access the file server. Presumably it will be one of these hosts. 

  ![SMB logon to DC]({{site.baseurl}}/assets/images/posts/DD-4-1.png)

Given they are connecting via SMB, lets parse the Microsoft-Windows-SmbClient%4Connectivity.evtx and Microsoft-Windows-SmbClient%4Security.evtx eventlogs and see what they tell us.

In our event log timeline we see the Event ID 30803 and the target system 10.1.1.226 (`corp-file.alien.local`) : `This indicates a problem with the underlying network or transport, such as with TCP/IP, and not with SMB. A firewall that blocks TCP port 445, or TCP port 5445 when using an iWARP RDMA adapter, can also cause this issue.`

Supporting this is Event ID 31010: `The SMB client failed to connect to the share.`

  ![SMB Failed logon]({{site.baseurl}}/assets/images/posts/DD-4-2.png)

<h5>Flag: corp-file</h5>

### DD-5
<h5>Unable to make it onto one server, the actor must have headed for another! What tool did they use to execute commands on that server? Flag format: toolname</h5>

From DD-4 we saw that they attempted to access corp-file as well as corp-dc. At this point I'll add `corp-dc` as a data source into Autopsy and also run the eventlog parser, as well as use MFTEcmd.exe to create an MFT output.

```
MFTECmd.exe -f "`$MFT" --csv yourlocation\artefacts\corp-dc.alien.local\dc\Collection-corp-dc.alien.local-2021-04-06_02_12_12__0000_GMT\C --csvf corp-dc-mft.csv
```

Reviewing the eventlogs in Autopsy for corp-dc, we come across an item in the system event log - Event ID 7045: A new service was installed in the system. 

  ![EventID 7045]({{site.baseurl}}/assets/images/posts/DD-5.png)

PsExec is a tool included in the Sysinternals Suite created by Mark Russinovich. Originally, it was intended as a convenience tool for system administrators so they could perform maintenance tasks by running commands on remote hosts. By providing the address of a target host, a valid user and a password, you can get control of a machine remotely. When psexec is used to run something on a remote system, it works by creating a new service executable called psexesvc.exe and runs the desired command.

<h5>Flag: psexec</h5>

### DD-6
<h5>Combining their domain credentials and their remote execution method, the actor proceeded to run a Windows utility that produced some output. What is the full file path of that utility on disk? Flag format: c:\a\file\path\file.ext</h5>

Knowing that there was "some output", I looked at the MFT output to see if I could see a likely file, and something did jump out at me ... `ad.zip` in the C:\temp directory. So filtering on the ParentPath .\temp I now have a good starting place and an idea of what has happened.

  ![temp directory contents]({{site.baseurl}}/assets/images/posts/DD-6-1.png)

There are two directories that were created during our attacker access, Active Directory and registry, containing ntds.jfm and ntds.dit, and SYSTEM and SECURITY files respectively. If you arent sure what is going on by this stage, its a good amount of information to turn to google to get some clues.

The Ntds.dit file is a database that stores Active Directory data, including information about user objects, groups, and group membership. It includes the password hashes for all users in the domain. 

Utilising the inbuilt tool 'Ntdsutil', the ntds.dit file and the system registry file can be copied to a location of choice, and utilising those two files password cracking can be conducted offline. This <a href="https://www.netwrix.com/ntds_dit_security_active_directory.html">post</a> outlines the commands and the summary very well.

I then did a keyword search in Autopsy across the event logs and found the following event confirming the use of ntdsutil and gives us the exact location: C:\Windows\System32\ntdsutil.exe.

  ![ntdsutil usage]({{site.baseurl}}/assets/images/posts/DD-6-2.png)

Reviewing the event log timeline in Autopsy you can see multiple events related to the use of ntdsutil and the output directories and when the PSEXECSVC completed.

  ![ntdsutil usage]({{site.baseurl}}/assets/images/posts/DD-6-3.png)

For more information and context on this style of attack:
* <a href="https://www.puckiestyle.nl/extracting-password-hashes-from-the-ntds-dit-file/">extracting-password-hashes-from-the-ntds-dit-file</a>
* <a href="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753343(v=ws.11)?redirectedfrom=MSDN">Ntdsutil</a>
* <a href="https://attack.mitre.org/techniques/T1003/003/">OS Credential Dumping: NTDS</a>

<h5>Flag: C:\Windows\System32\ntdsutil.exe</h5>

### DD-7
<h5>Now with access to all domain credentials, which domain account did the actor use to successfully access the server they failed to access previously?Flag format: username</h5>

What we know so far:
* They had previously tried and failed to access the corp-file system.
* From looking at the MFT items, ad.zip was created on disk at 06:01:30. 
* We have a clue about which system to check and also a time frame. 
* We also know that EventID 4648 showed us the attempts made to access the system from corp-webdev using SMB.

Time to add `corp-file.alien.local` artefacts to the Autopsy case and parse the Eventlogs (I'll also parse the MFT at the same time).

From our Autopsy event log table:
* 2021-04-01 06:18:00 - SMB access attempt from corp-webdev to corp-file using account `admin`
* 2021-04-01 06:18:00 - EventID 4625 (An account failed to log on) in corp-file security event log.
* 2021-04-01 06:18:53 - SMB access attempt from corp-webdev to corp-file using account `re_bmilton`
* 2021-04-01 06:18:53 - EventID 4624 (An account was successfully logged on) in corp-file security event log.

  ![Successful logon with re_bmilton]({{site.baseurl}}/assets/images/posts/DD-7-1.png)

<h5>Flag: re_bmilton</h5>

### DD-8
<h5>Looks like the actor has re-used some of their earlier reconnaissance tools and once again left evidence on disk in a file. What time (UTC) was this file created? Flag format: yyyy-mm-dd hh:mm:ss</h5>

This is a bit of a tricky one. We need to remember that the attacker has been staging their attack from `corp-webdev` and the access to the file server was over SMB. If we take a look at the MFT output from `corp-webdev` for this timeframe we'll see a file in the Windows\Temp directory called filedir.txt created at 2021-04-01 6:19:19.

<h5>Flag: 2021-04-01 6:19:19</h5>