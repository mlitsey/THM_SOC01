# ItsyBitsy

Put your ELK knowledge together and investigate an incident.

[Link](https://tryhackme.com/room/itsybitsy)


## _**1: Introduction**_

In this challenge room, we will take a simple challenge to investigate an alert by IDS regarding a potential C2 communication.

Room Machine

Before moving forward, deploy the machine. When you deploy the machine, it will be assigned an IP **Machine IP**: `MACHINE_IP`. The machine will take up to 3-5 minutes to start. Use the following credentials to log in and access the logs in the Discover tab.


## _**2: Scenario - Investigate a potential C2 communication alert**_

**Scenario**

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern THM:{ \_\_\_\_\_\_\_\_ }. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.  

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.

**Questions**

How many events were returned for the month of March 2022?

- 1482

![](2023-03-29-07-19-07.png)

What is the IP associated with the suspected user in the logs?

- 192.166.65.54

The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

- bitsadmin

The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

- pastebin.com

What is the full URL of the C2 to which the infected host is connected?

- pastebin.com/yTg0Ah6a

A file was accessed on the filesharing site. What is the name of the file accessed?

- secret.txt

The file contains a secret code with the format THM{_____}.

- THM{SECRET__CODE}


