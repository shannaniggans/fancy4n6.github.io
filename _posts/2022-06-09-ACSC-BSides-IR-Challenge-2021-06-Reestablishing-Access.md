---
layout: post
title: ACSC BSides IR Challenge 2021 - 06 - Reestablishing Access
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

## 6 - Reestablishing Access

> Out of the blue, it seems that the actor has had issues accessing the network. Were they kicked out for good?

Somewhere along the way the actors lost access to their webshell. So in this section we need to take a look at what happened to the webshell and then how they got themselves back into the network.

> <a target="_blank" href="https://attack.mitre.org/tactics/TA0003/">TA003</a> - **Persistence** consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.
> <br>See also <a target="_blank" href="https://attack.mitre.org/techniques/T1505/003/">T1505.003: Server Software Component: Web Shell</a>

To complete this section I have used the following tools:
* MFT output spreadsheet.
* Splunk for the IIS logs.
* Autopsy - ParseEVTX Python Ingest Module.
* MFTECmd with some different output options.

**Note: See <a href="{{ site.baseurl }}/ACSC-BSides-IR-Challenge-2021-Setup/" target="_blank">this page </a>for tool set up and explanations.**

### RA-1
<h5>The actor appears to have suddenly had some trouble accessing sample 2. What time (UTC) did they first fail to use it? Flag format: yyyy-mm-dd hh:mm:ss</h5>

First, let's revisit what we've already collected about the two malware samples.

<table class="table table-striped table-sm small w-auto table-responsive">
  <caption class="figure-caption text-center">Table: Our malware samples</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col">ACSC Name</th>
      <th scope="col">Created</th>
      <th scope="col">Host</th>
      <th scope="col">File Name</th>
      <th scope="col">Location</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">Sample-1</th>
      <td>2021-04-01 2:50:43</td>
      <td>dmz-webpub</td>
      <td>1617245455.5314393.dll</td>
      <td>C:\Windows\Temp</td>
    </tr>
    <tr>
      <th scope="row">Sample-2</th>
      <td>2021-04-01 03:03:16</td>
      <td>corp-webdev</td>
      <td>App_Web_euav215z.dll</td>
      <td>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\</td>
    </tr>
  </tbody>
</table>

Sample 2 we know was dropped on `corp-webdev` so we will need to go back and revisit our evidence items here.

We know they gained access and were using a GET request to /submit.aspx. So lets narrow down to their access attempts in Splunk to find out when they stopped being successful.
```
index="acsc_ir_challenge_2021" 
| where sourcetype = "iis" 
| where cs_uri_stem= "/submit.aspx"
| sort _time 
| table _time, c_ip, cs_uri_stem, cs_method, sc_status
```
Breaking down what we see in the logs in terms of requests to the server and the responses.
<table class="table table-striped table-sm small auto">
  <caption class="figure-caption text-center">Table: IIS Log Event Definitions</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col" >HTTP Event</th>
      <th scope="col">Definition</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row">Request: GET</th>
      <td><a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET">GET</a> is an HTTP method for requesting data from the server. Requests using the HTTP GET method should only fetch data, cannot enclose data in the body of a GET message, and <mark>should not have any other effect on data on the server</mark>.</td>
    </tr>
    <tr>
      <th scope="row">Request: POST</th>
      <td>The HTTP <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST">POST</a> method sends data to the server. A POST request is typically sent via an HTML form and <mark>results in a change on the server</mark>.</td>
    </tr>
    <tr>
      <th scope="row">Response: 200</th>
      <td>The HTTP 200 OK success status response code indicates that the request has succeeded. A 200 response is cacheable by default.</td>
    </tr>
    <tr>
      <th scope="row">Response: 413</th>
      <td>The HTTP 413 Payload Too Large response status code indicates that the request entity is larger than limits defined by server; the server might close the connection or return a Retry-After header field.</td>
    </tr>
    <tr>
      <th scope="row">Response: 404 </th>
      <td>The HTTP 404 Not Found response status code indicates that the server cannot find the requested resource. Links that lead to a 404 page are often called broken or dead links and can be subject to link rot</td>
    </tr>
  </tbody>
</table>

So we are looking for when they started to have trouble accessing, which would be the 404 response. Narrowing it down again:
```
index="acsc_ir_challenge_2021" 
| where sourcetype = "iis" 
| where cs_uri_stem= "/submit.aspx"
| where sc_status= "404"
| sort _time 
| table _time, c_ip, cs_uri_stem, cs_method, sc_status
```

   ![Response 404 results]({{site.baseurl}}/assets/images/posts/RA-1.png)

<h5>Flag: 2021-04-05 21:40:19</h5>

### RA-2
<h5>"It looks like some files related to sample 2, the actor's webshell, have been flagged and removed. Looks like they were using a well known tool! What is the common name for sample 2? Flag format: ToolName"
</h5>
"Flagged and removed" to me sounds like AV got the file, so that's where I'll check. In Autopsy I filtered on Source Name: Microsoft-Windows-Windows Defender and checked around 2021-04-05 21:40:19.

There are two events:
<br><kbd>corp-webdev.alien.local</kbd>

```
2021-04-05 22:01:21.622398	 
ALIEN 
dev_agardner 
S-1-5-21-3316040739-64797688-1164660000-1118 
Backdoor:MSIL/Chopper.F!dha
https://go.microsoft.com/fwlink/?linkid=37020&name=Backdoor:MSIL/Chopper.F!dha&threatid=2147776854&enterprise=0 
file:_C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\App_Web_euav215z.dll 
Severe
Backdoor 
AV: 1.333.1660.0, AS: 1.333.1660.0 
1.1.17900.7	
```
<kbd>dmz-webpub.alien.local</kbd>
```
2021-04-05 22:55:41.744503	
DMZ-WEBPUB 
Administrator 
S-1-5-21-4089384500-2623859888-3969791207-500 
Backdoor:MSIL/Chopper.F!dha
https://go.microsoft.com/fwlink/?linkid=37020&name=Backdoor:MSIL/Chopper.F!dha&threatid=2147776854&enterprise=0 
file:_C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\a056c683\f67bca3c\App_Web_aa0aecbt.dll 
Severe
Backdoor 
AV: 1.333.1660.0, AS: 1.333.1660.0 
1.1.17900.7	
```
I am very familiar with this webshell backdoor and know it as ChinaChopper.

For some insights into ChinaChopper, check out this <a target="_blank" href="https://www.mandiant.com/resources/breaking-down-china-chopper-web-shell-part-i">blog</a> from Mandiant.

<h5>Flag: ChinaChopper</h5>

### RA-3
<h5>The actor wasn't able to move their webshell to the second web server as easily this time due to an unavailable service. What time did the replication stop working? Flag format: yyyy-mm-dd hh:mm:ss</h5>

DFS Replication.evtx is likely where we will find this evidence.
on `dmz-webpub` there are 7 events at 2021-04-01 08:38:00.344700 with the following event codes:
<table class="table table-striped table-sm small auto">
  <caption class="figure-caption text-center">Table: DFS Replication Event Log Event Identifier Codes.</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col" >HTTP Event</th>
      <th scope="col">Definition</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row">4010</th>
      <td>	DFSr Service detected that the replicated folder at local path %2</td>
    </tr>
    <tr>
      <th scope="row">5016</th>
      <td>The replication mode on the connection to partner %2 has changed.</td>
    </tr>
    <tr>
      <th scope="row">6804</th>
      <td>DFSr Service has detected that no connections are configured for</td>
    </tr>
    <tr>
      <th scope="row">3006</th>
      <td>	DFSr Service has detected that replication group %2 was removed.</td>
    </tr>
  </tbody>
</table>
Reference: <a target="_blank" href="https://social.technet.microsoft.com/wiki/contents/articles/52581.list-of-dfs-replication-error-codes.aspx">List of DFS Replication Error codes</a>

%2 in this case is dfsrtest which matches our previous discoveries.

<h5>Flag: 2021-04-01 08:38:00</h5>

### RA-4
<h5>The actor managed to move their webshell using one of their previous tricks and compromised domain credentials. What time did they establish a connection between the two hosts to facilitate moving their webshell? Flag format: yyyy-mm-dd hh:mm:ss</h5>

To get an idea of the timeframe i went back to splunk and took a look at the actor activities since they stopped being successful.

```
index="acsc_ir_challenge_2021"
| where sourcetype = "iis"
| where c_ip="13.54.35.87"
| sort _time
| table _time, c_ip, cs_uri_stem, cs_method, sc_status
```
with the date filter set to "Since 04/05/2021 21:40:00.000"

<table class="table table-striped table-sm small auto">
  <caption class="figure-caption text-center">Table: IIS Logs.</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col">_time_</th>
      <th scope="col">c_ip</th>
      <th scope="col">cs_uri_stem</th>
      <th scope="col">cs_method</th>
      <th scope="col">sc_status</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row">2021-04-05 21:40:19</th>
      <td>13.54.35.87</td>
      <td>/submit.aspx</td>
      <td>POST</td>
      <td>404</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 21:40:36</th>
      <td>13.54.35.87</td>
      <td>/submit.aspx</td>
      <td>POST</td>
      <td>404</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 21:55:25</th>
      <td>13.54.35.87</td>
      <td>/Default.aspx</td>
      <td>GET</td>
      <td>200</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 21:57:12</th>
      <td>13.54.35.87</td>
      <td>/submit.aspx</td>
      <td>GET</td>
      <td>404</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 22:08:24</th>
      <td>13.54.35.87</td>
      <td>/Default.aspx</td>
      <td>GET</td>
      <td>200</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 23:15:46</th>
      <td>13.54.35.87</td>
      <td>/Telerik.Web.UI.WebResource.axd</td>      
      <td>POST</td>
      <td>200</td>    
    </tr>
    <tr>
      <th scope="row">2021-04-05 23:16:07</th>
      <td>13.54.35.87</td>
      <td>/global.aspx</td>
      <td>POST</td>
      <td>200</td>
    </tr>
    <tr>
      <th scope="row">2021-04-05 23:16:25</th>
      <td>13.54.35.87</td>
      <td>/global.aspx</td>
      <td>POST</td>
      <td>200</td>
    </tr>
  </tbody>
</table>

Sometimes this data can tell a bit of a story. In this case, what it looks like to me is that the actor lost access to their webshell via submit.aspx. To check whether the webserver was still up they browsed to default.aspx and could access, tried their webshell again and failed, then roughly an hour and a bit later they exploited the telerik vulnerability again to load another webshell and regain access. The new webshell was /global.aspx.

So they have no reestablished external access at 2021-04-05 23:16:07 when they regained access via global.aspx. 

So we are then looking for events after this time for when they may have transferred files from dmz-webpub to corp-webdev over SMB as they did in the past.

   ![Corresponding Event logs]({{site.baseurl}}/assets/images/posts/RA-2.png)

<table class="table table-striped table-sm small auto">
  <caption class="figure-caption text-center">Table: Security eventlog timeline in Autopsy.</caption>
  <thead class="thead-dark">
    <tr>
      <th scope="col">Computer Name</th>
      <th scope="col">Event ID</th>
      <th scope="col">Event Time</th>
      <th scope="col">Detail</th>
    </tr>
  </thead>
<tbody>
    <tr>
      <th scope="row">dmz-webpub.alien.local</th>
      <td>4648: A logon was attempted using explicit credentials</td>
      <td>2021-04-05 23:32:18.724890	</td>
      <td>user ALIEN\dev_agardner attempting to log on to corp-webdev.alien.local over port 445</td>
    </tr>
    <tr>
      <th scope="row">corp-dc.alien.local	</th>
      <td>4776: The domain controller attempted to validate the credentials for an account</td>
      <td>2021-04-05 23:32:18.738127</td>
      <td>dev_agardner authenticated from DMZ-WEBPUB</td>
    </tr>
    <tr>
      <th scope="row">corp-webdev.alien.local	</th>
      <td>4672: Special privileges assigned to new logon</td>
      <td>2021-04-05 23:32:18.740792</td>
      <td>user ALIEN\dev_agardner</td>
    </tr>
    <tr>
      <th scope="row">corp-webdev.alien.local	</th>
      <td>4624: An account was successfully logged on</td>
      <td>2021-04-05 23:32:18.740873</td>
      <td>user ALIEN\dev_agardner, Logon Type 3 from DMZ-WEBPUB (10.1.0.80)</td>
    </tr>
  </tbody>
</table>

<h5>Flag: 021-04-05 23:32:18</h5>

### RA-5
<h5>What was the password of the actor's new webshell? Flag format: password</h5>
From RA-4 we now know that the new webshell was global.aspx. The answer relies on you knowing that within the MFT there is a $DATA attribute. For short text file and files smaller than 700 bytes, they are "resident" in the MFT within the $DATA attribute and therefore we can extract the contents.

There are a few tools that we can do this with. Since we have already exported the MFT to a csv, we can find the file information:
- Entry number: 302095
- Sequence number: 28

Running MFTECmd.exe again and focusing on this specific file will show us what is in the $DATA field:
```
F:\EZTools\Get-ZimmermanTools\MFTECmd.exe -f "(location)\ACSC\ACSC_IR_Challenge_2021\artefacts\corp-webdev.alien.local\C\`$MFT" --de 302095-28
```
Right at the bottom when we scroll down we see the data and the webshell.

   ![webshell contents]({{site.baseurl}}/assets/images/posts/RA-3.png)

<code>(Request.Item[<mark>"tinfoil"</mark>]</code>

<h5>Flag: tinfoil</h5>

### M-6
<h5>What was the md5 hash of the original webshell (sample 2)?</h5>
Our sample 2 file information looked like this:
- Entry number: 638
- Sequence number: 58

Running MFTECmd.exe again and focusing on this specific file will show us what is in the $DATA field:
```
F:\EZTools\Get-ZimmermanTools\MFTECmd.exe -f "(location)\ACSC\ACSC_IR_Challenge_2021\artefacts\corp-webdev.alien.local\C\`$MFT" --de 638-58
```

   ![webshell contents of sample 2]({{site.baseurl}}/assets/images/posts/RA-4.png)

The flag answer they gave was `8a0ff044f892d72dbfb8fe9d6a395d47` which I cannot replicate. If anyone can point me in the right direction I'd appreciate it!

   ![CyberChef Hash results]({{site.baseurl}}/assets/images/posts/RA-5.png)

#### UPDATE
With some assistance we went back to the ACSC for clarification and there was actually a new line character at the end of the webshell code that when I copied the ASCII output was not obvious. To replicate and get the answer i took the HEX, converted to ascii in cyberchef and then took the MD5.

   ![CyberChef Hash results]({{site.baseurl}}/assets/images/posts/RA-6.png)

<h5>Flag: 8a0ff044f892d72dbfb8fe9d6a395d47</h5>

