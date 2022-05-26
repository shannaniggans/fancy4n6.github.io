---
layout: posts
categories: Tools
tags: [ Cado Autopsy Timesketch Tools ]
title: Using Cado Host for a quick triage
date: '2022-05-23 +1000'
last_modified: '2022-05-23 +1000'
---






> Cado Host allows you to acquire evidence from on premises systems (via the Cado Host agent) and write that evidence to cloud storage for processing.

Cado Host comes as an executable and has been made available for the community as a <a href="https://www.cadosecurity.com/cado-host/">download.</a> I have been using Cado Host as part of my workflow for a while now as it makes grabbing a triage package from systems nice and easy. I can be scaled to collect packages from a large number of systems via group policy or other systems management software, or just one. Data is collected and stored in a zip file and these package files can be automatically uploaded to a cloud provider, or saved on an attached USB drive or network share.

### 1. Acquiring artefacts with Cado Host.
For this example I will use Cado Host to pull the artefacts and save to a local drive.

1. Download and extract Cado Host to an external USB drive that you'll plug into the collection system and will also be used to save the data.
2. I'm running this on a windows system, so I'll open Command Prompt, but making sure to open with Administrative privileges - Right click and "Run as Administrator".
3. Change directory to where you have Cado Host extracted. Running cado-host.exe will start the process, but we don't want to start just yet as we'll need to set some configuration items.
4. The following are the commandline parameters support by Cado Host:
   
    ```
    Usage:
    cado-host [options]

    Options:
    --light                              Exclude large files (over 100 Mb) from the collection
    --storage <storage>                  The cloud storage to use (aws/azure/google). A File will be stored locally if
                                        none selected
    --bucket <bucket>                    The AWS Bucket to store data in
    --access_key <access_key>            The AWS Access Key
    --secret_key <secret_key>            The AWS Secret Key
    --region <region>                    The bucket region eg; US-EAST-1 (Optional)
    --account_name <account_name>        The Azure Account Name
    --container_name <container_name>    The Azure Container Name
    --sas_string <sas_string>            The Azure SAS String. Surround with " i.e. --sas_string="string"
    --gcp_bucket <gcp_bucket>            The Google Cloud Bucket to store data in
    --gcp_access_key <gcp_access_key>    The Google Cloud Access Key
    --gcp_secret_key <gcp_secret_key>    The Google Cloud Secret Key
    --version                            Show version information
    -?, -h, --help                       Show help and usage information
    ```
5. As we are collecting from a local system, do a connected drive, the package will be downloaded into the same folder we are running cado host from.
6. If you want to specify another location to download and save the zip file to, rename "example_config.cfg" to "config.cfg" and edit the file.
   ![config.cfg]({{site.baseurl}}/assets/imgs/config.cfg.png)
7. Change the destination_folder to wherever you want to save the zip file.
8. The full listing of artefacts that Cado Host collects by default is available in the <a href="https://docs.cadosecurity.com/cado-host/artifacts">documentation</a>. If there are additional files you want to collect as well, for example you know the particular directory an attacker has been using on the network, you can add that to the collection with the `--additional_files` parameter when building your collection command.
9. Once the process is finished:
   ```
   C:\Users\frenz\Downloads\CadoHost_MS_Win\win64>cado-host.exe
    No config.cfg file found - Reading in Command Line Parameters
    Not running in Light Mode, large files will be included
    Running as Administrator
    Saving Start Log
    No Storage Set (--storage). Archive will be created locally.
    Successfully saved Start Log to storage
    Windows System detected
    Creating archive
    Finished adding files to zip
    Deleted Temporary Files
    No Storage Set (--storage). Archive will be created locally.
    Finished
    ```
10. You'll have two files, one text file and one zip file. The text file has an output of running processes and active network connections. The zip file contains our artefacts.

That process is very simple. And you can see that running cado-host across a large environment would be quick and easy and you could have all the zip files uploaded directly to a cloud storage area ready for processing. But now you have all these zip files (or even just one zip file), what is a quick way to get some answers.

### 2. Looking at what we've got
The column on the left shows the data that Cado Host will look to extract as part of the acquisition process and the right hand column is where I'll jot down what I'll use to parse the item and get it into a format to import into TimeSketch. We might not have all of these artefacts on our target system(s), and remembering that we're looking to do a quick and dirty timeline triage, not necessarily timeline everything that's been collected.


| Artefact                                                                        | How we'll deal with it    |
|---------------------------------------------------------------------------------|---------------------------|
| Running Processes                                                               |                           |
| Active Network Connections                                                      |                           |
| $MFT                                                                            | MFTECmd > csv             |
| ALLUSERSPROFILE\McAfee\DesktopProtection\AccessProtectionLog.txt                |                           |
| APPDATA\LocalLow\Sun\Java\Deployment\cache\6.0                                  |                           |
| APPDATA\Local\Apple Computer\Safari\Cookies\Cookies.binarycookies               |                           |
| APPDATA\Local\ConnectedDevicesPlatform                                          |                           |
| APPDATA\Local\Google\Chrome\User Data\Default\Extensions                        |                           |
| APPDATA\Local\Google\Chrome\User Data\Default\History                           |                           |
| APPDATA\Local\Google\Chrome\User Data\Default\Web Data                          |                           |
| APPDATA\Local\Microsoft\Windows\Explorer                                        |                           |
| APPDATA\Local\Microsoft\Windows\FileHistory\Configuration                       |                           |
| APPDATA\Local\Microsoft\Windows\UsrClass.dat                                    | Autopsy > Recent Activity |
| APPDATA\Local\Microsoft\Windows\UsrClass.dat.LOG1                               |                           |
| APPDATA\Local\Microsoft\Windows\UsrClass.dat.LOG2                               |                           |
| APPDATA\Local\Microsoft\Windows\WebCache                                        |                           |
| APPDATA\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt |                           |
| APPDATA\Roaming\Microsoft\Windows\Recent                                        |                           |
| APPDATA\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\                 |                           |
| APPDATA\Roaming\Mozilla\Firefox\Profiles\                                       |                           |
| APPDATA\Roaming\Opera\Opera\global_history.dat                                  |                           |
| APPDATA\Roaming\Opera\Opera\typed_history.xml                                   |                           |
| NTUSER.DAT                                                                      | Autopsy > Recent Activity |
| NTUSER.DAT.LOG1                                                                 |                           |
| NTUSER.DAT.LOG2                                                                 |                           |
| PROGRAMDATA\McAfee\DesktopProtection\AccessProtectionLog.txt                    |                           |
| PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup                       |                           |
| SYSTEMROOT\AppCompat\Programs\AmCache.hve                                       |                           |
| SYSTEMROOT\Prefetch                                                             | Autopsy > Recent Activity |
| SYSTEMROOT\SchedLgU.Txt                                                         |                           |
| SYSTEMROOT\System32\Config\AppEvent.evt                                         | Autopsy > ParseEvtx       |
| SYSTEMROOT\System32\Config\SecEvent.evt                                         | Autopsy > ParseEvtx       |
| SYSTEMROOT\System32\Config\SysEvent.evt                                         | Autopsy > ParseEvtx       |
| SYSTEMROOT\System32\LogFiles\W3SVC1                                             |                           |
| SYSTEMROOT\System32\Tasks                                                       |                           |
| SYSTEMROOT\System32\config\SAM                                                  | Autopsy > Recent Activity |
| SYSTEMROOT\System32\config\SAM.LOG1                                             |                           |
| SYSTEMROOT\System32\config\SAM.LOG2                                             |                           |
| SYSTEMROOT\System32\config\SECURITY                                             | Autopsy > Recent Activity |
| SYSTEMROOT\System32\config\SECURITY.LOG1                                        |                           |
| SYSTEMROOT\System32\config\SECURITY.LOG2                                        |                           |
| SYSTEMROOT\System32\config\SOFTWARE                                             | Autopsy > Recent Activity |
| SYSTEMROOT\System32\config\SOFTWARE.LOG1                                        |                           |
| SYSTEMROOT\System32\config\SOFTWARE.LOG2                                        |                           |
| SYSTEMROOT\System32\config\SYSTEM                                               | Autopsy > Recent Activity |
| SYSTEMROOT\System32\config\SYSTEM.LOG1                                          |                           |
| SYSTEMROOT\System32\config\SYSTEM.LOG2                                          |                           |
| SYSTEMROOT\System32\drivers\etc\hosts                                           |                           |
| SYSTEMROOT\System32\sru                                                         |                           |
| SYSTEMROOT\System32\winevt\logs                                                 |                           |
| SYSTEMROOT\Tasks                                                                |                           |
| SYSTEMROOT\inf\setupapi.dev.log                                                 |                           |
| SYSTEMROOT\inf\setupapi.log                                                     |                           |
| inetpub\logs\LogFiles                                                           |                           |
|                                                                                 |                           |
| Additional Files                                                                |                           |
| \Windows\System32\Logfiles\SUM                                                  | Autopsy > UAL Parser      |














### 3. Using Autopsy to parse the artefacts.
I already have a post on setting up <a href="{{site.baseurl}}/tools/2022/05/03/Autopsy.html">Autopsy</a>. So go ahead and set up a new case and unzip the Cado Host artefact zip file.
> Tip: Use 7zip or similar to uncompress the file, Using Windows unzip may cause errors with file length.

1. Ensure that your <a href="https://github.com/markmckinnon/Autopsy-Plugins">Autopsy python plugins are up to date.</a>
2. 




### 3. What about the $MFT?








