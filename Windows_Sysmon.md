# Sysmon

Learn how to utilize Sysmon to monitor and log your endpoints and environments.

## _**1: Introduction**_

Sysmon, a tool used to monitor and log events on Windows, is commonly used by enterprises as part of their monitoring and logging solutions. Part of the Windows Sysinternals package, Sysmon is similar to Windows Event Logs with further detail and granular control.

![Microsoft Security logo](https://wp.technologyreview.com/wp-content/uploads/2020/02/ms-securitylogostackedc-grayrgb-hero-copy-small-1.png)

This room uses a modified version of the [Blue](https://tryhackme.com/room/blue) and [Ice](https://tryhackme.com/room/ice) boxes, as well as Sysmon logs from the Hololive network lab.

_Before completing this room we recommend completing the [Windows Event Log](https://tryhackme.com/room/windowseventlogs) room. It is also recommended to complete the Blue and Ice rooms to get an understanding of vulnerabilities present however is not required to continue._


## _**2: Sysmon Overview**_

From the Microsoft Docs, "System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. By collecting the events it generates using Windows Event Collection or SIEM agents and subsequently analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network."

Sysmon gathers detailed and high-quality logs as well as event tracing that assists in identifying anomalies in your environment. Sysmon is most commonly used in conjunction with security information and event management (SIEM) system or other log parsing solutions that aggregate, filter, and visualize events. When installed on an endpoint, Sysmon will start early in the Windows boot process. In an ideal scenario, the events would be forwarded to a SIEM for further analysis. However, in this room, we will focus on Sysmon itself and view the events on the endpoint itself with Windows Event Viewer.

Events within Sysmon are stored in `_Applications and Services Logs/Microsoft/Windows/Sysmon/Operational_`

Sysmon Config Overview

Sysmon requires a config file in order to tell the binary how to analyze the events that it is receiving. You can create your own Sysmon config or you can download a config. Here is an example of a high-quality config that works well for identifying anomalies created by SwiftOnSecurity: [Sysmon-Config.](https://github.com/SwiftOnSecurity/sysmon-config) Sysmon includes 29 different types of Event IDs, all of which can be used within the config to specify how the events should be handled and analyzed. Below we will go over a few of the most important Event IDs and show examples of how they are used within config files.

When creating or modifying configuration files you will notice that a majority of rules in sysmon-config will exclude events rather than include events. This will help filter out normal activity in your environment that will in turn decrease the number of events and alerts you will have to manually audit or search through in a SIEM. On the other hand, there are rulesets like the ION-Storm sysmon-config fork that takes a more proactive approach with it's ruleset by using a lot of include rules. You may have to modify configuration files to find what approach you prefer. Configuration preferences will vary depending on what SOC team so prepare to be flexible when monitoring.

_Note: As there are so many Event IDs Sysmon analyzes. we will only be going over a few of the ones that we think are most important to understand._

Event ID 1: Process Creation

This event will look for any processes that have been created. You can use this to look for known suspicious processes or processes with typos that would be considered an anomaly. This event will use the CommandLine and Image XML tags.

`<RuleGroup name="" groupRelation="or">  
<ProcessCreate onmatch="exclude">  
  <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>  
</ProcessCreate>  
</RuleGroup>`

The above code snippet is specifying the Event ID to pull from as well as what condition to look for. In this case, it is excluding the svchost.exe process from the event logs.

Event ID 3: Network Connection

The network connection event will look for events that occur remotely. This will include files and sources of suspicious binaries as well as opened ports. This event will use the Image and DestinationPort XML tags. 

`<RuleGroup name="" groupRelation="or">  
<NetworkConnect onmatch="include">  
  <Image condition="image">nmap.exe</Image>  
  <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>  
</NetworkConnect>  
</RuleGroup>`

The above code snippet includes two ways to identify suspicious network connection activity. The first way will identify files transmitted over open ports. In this case, we are specifically looking for nmap.exe which will then be reflected within the event logs. The second method identifies open ports and specifically port 4444 which is commonly used with Metasploit. If the condition is met an event will be created and ideally trigger an alert for the SOC to further investigate.

Event ID 7: Image Loaded

This event will look for DLLs loaded by processes, which is useful when hunting for DLL Injection and DLL Hijacking attacks. It is recommended to exercise caution when using this Event ID as it causes a high system load. This event will use the Image, Signed, ImageLoaded, and Signature XML tags. 

`<RuleGroup name="" groupRelation="or">  
<ImageLoad onmatch="include">  
  <ImageLoaded condition="contains">\Temp\</ImageLoaded>  
</ImageLoad>  
</RuleGroup>  
`  

The above code snippet will look for any DLLs that have been loaded within the \\Temp\\ directory. If a DLL is loaded within this directory it can be considered an anomaly and should be further investigateded. 

Event ID 8: CreateRemoteThread

The CreateRemoteThread Event ID will monitor for processes injecting code into other processes. The CreateRemoteThread function is used for legitimate tasks and applications. However, it could be used by malware to hide malicious activity. This event will use the SourceImage, TargetImage, StartAddress, and StartFunction XML tags.

`<RuleGroup name="" groupRelation="or">  
<CreateRemoteThread onmatch="include">  
  <StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>  
  <SourceImage condition="contains">\</SourceImage>  
</CreateRemoteThread>  
</RuleGroup>  
`  

The above code snippet shows two ways of monitoring for CreateRemoteThread. The first method will look at the memory address for a specific ending condition which could be an indicator of a Cobalt Strike beacon. The second method will look for injected processes that do not have a parent process. This should be considered an anomaly and require further investigation. 

Event ID 11: File Created

This event ID is will log events when files are created or overwritten the endpoint. This could be used to identify file names and signatures of files that are written to disk. This event uses TargetFilename XML tags.  

`<RuleGroup name="" groupRelation="or">  
<FileCreate onmatch="include">  
  <TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>  
</FileCreate>  
</RuleGroup>`   

The above code snippet is an example of a ransomware event monitor. This is just one example of a variety of different ways you can utilize Event ID 11.

Event ID 12 / 13 / 14: Registry Event

This event looks for changes or modifications to the registry. Malicious activity from the registry can include persistence and credential abuse. This event uses TargetObject XML tags.  

`<RuleGroup name="" groupRelation="or">  
<RegistryEvent onmatch="include">  
  <TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>  
</RegistryEvent>  
</RuleGroup>`  

The above code snippet will look for registry objects that are in the _"Windows\\System\\Scripts"_ directory as this is a common directory for adversaries to place scripts to establish persistence.

Event ID 15: FileCreateStreamHash

This event will look for any files created in an alternate data stream. This is a common technique used by adversaries to hide malware. This event uses TargetFilename XML tags.

`<RuleGroup name="" groupRelation="or">  
<FileCreateStreamHash onmatch="include">  
  <TargetFilename condition="end with">.hta</TargetFilename>  
</FileCreateStreamHash>  
</RuleGroup>`   

The above code snippet will look for files with the .hta extension that have been placed within an alternate data stream.

Event ID 22: DNS Event

This event will log all DNS queries and events for analysis. The most common way to deal with these events is to exclude all trusted domains that you know will be very common "noise" in your environment. Once you get rid of the noise you can then look for DNS anomalies. This event uses QueryName XML tags. 

`<RuleGroup name="" groupRelation="or">  
<DnsQuery onmatch="exclude">  
  <QueryName condition="end with">.microsoft.com</QueryName>  
</DnsQuery>  
</RuleGroup>` 

The above code snippet will get exclude any DNS events with the .microsoft.com query. This will get rid of the noise that you see within the environment. 

There are a variety of ways and tags that you can use to customize your configuration files. We will be using the ION-Storm and SwiftOnSecurity config files for the rest of this room however feel free to use your own configuration files.

## _**3: Installing and Preparing Sysmon**_

