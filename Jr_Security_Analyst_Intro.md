# **Cyber Defense Frameworks**

## **--Junior Security Analyst Intro--**
 
### **A career as a Junior (Associate) Security Analyst**
In the Junior Security Analyst role, you will be a Triage Specialist. You will spend a lot of time triaging or monitoring the event logs and alerts.

### **Security Operations Center**
- SOC (Security Operations Center)
- TTPs (Tactics, Techniques, and Procedures)
- CISA (Cybersecurity & Infrastructure Security Agency)
- SIEM (Security information and event management)
- EDR (endpoint detection and response)

### **A day In the life of a Junior (Associate) Security Analyst**
- IPS (intrusion prevention system)
- IDS (intrusion detection system)

There are many open-source databases out there like AbuseIPDB, Cisco Talos Intelligence, where you can perform a reputation and location check for the IP address.

## **--Pyramid of Pain--**
This well-renowned concept is being applied to cybersecurity solutions like [Cisco Security](https://gblogs.cisco.com/ca/2020/08/26/the-canadian-bacon-cisco-security-and-the-pyramid-of-pain/), [SentinelOne](https://www.sentinelone.com/blog/revisiting-the-pyramid-of-pain-leveraging-edr-data-to-improve-cyber-threat-intelligence/), and [SOCRadar](https://socradar.io/re-examining-the-pyramid-of-pain-to-use-cyber-threat-intelligence-more-effectively/) to improve the effectiveness of CTI (Cyber Threat Intelligence), threat hunting, and incident response exercises.

![](2022-11-28-10-29-23.png)

### **Hash Values**
Hash Values are a numeric value of a fixed length that uniquely identifies data

- MD5 (Message Digest, defined by [RFC 1321](https://www.ietf.org/rfc/rfc1321.txt))
- SHA-1 (Secure Hash Algorithm 1, defined by [RFC 3174](https://tools.ietf.org/html/rfc3174))
- SHA-2 (Secure Hash Algorithm 2)

Check out [The DFIR Report](https://thedfirreport.com/) and [FireEye Threat Research Blogs](https://www.fireeye.com/blog/threat-research.html) for examples.

Various online tools can be used to do hash lookups like [VirusTotal](https://www.virustotal.com/gui/) and [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/?lang=en).

- IOC (indicatior of compromise)

### **IP Address**
Fast Flux is a DNS technique used by botnets to hide phishing, web proxying, malware delivery, and malware communication activities behind compromised hosts acting as proxies.

### **Domain Names**
Domain Names can be thought as simply mapping an IP address to a string of text.

- DNS (domain name system)

Punnycode attack: Punycode is a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding.

Attackers can hide the malicious domains under **URL Shorteners.** A URL Shortener is a tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL Shortener link. Attackers can use the following URL Shortening services to generate malicious links: 

- bit.ly
- goo.gl
- ow.ly
- s.id
- smarturl.it
- tiny.pl
- tinyurl.com
- x.co

You can see the actual website the shortened link is redirecting you to by appending "+" to it (see the examples below). Type the shortened URL in the address bar of the web browser and add the above characters to see the redirect URL.

### **Host Artifacts**
Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.

### **Network Artifacts**
A network artifact can be a user-agent string, C2 information, or URI patterns followed by the HTTP POST requests.An attacker might use a User-Agent string that hasn’t been observed in your environment before or seems out of the ordinary. The User-Agent is defined by [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616#page-145) as the request-header field that contains the information about the user agent originating the request.

[Any Run](https://any.run/)

### **Tools**
- C2 (command and control infrastructure)

Attackers would use the utilities to create malicious macro documents (maldocs) for spearphishing attempts, a backdoor that can be used to establish C2 (Command and Control Infrastructure), any custom .EXE, and .DLL files, payloads, or password crackers.

[MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources to provide you with access to the samples, malicious feeds, and YARA results

For detection rules, [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries.

Fuzzy hashing is also a strong weapon against the attacker's tools.
One of the examples of fuzzy hashing is the usage of [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html)

### **TTPs**
TTPs stands for Tactics, Techniques & Procedures. This includes the whole [MITRE](https://attack.mitre.org/) [ATT&CK Matrix](https://attack.mitre.org/), which means all the steps taken by an adversary to achieve his goal, starting from phishing attempts to persistence and data exfiltration. 

If you can detect and respond to the TTPs quickly, you leave the adversaries almost no chance to fight back. For, example if you could detect a [Pass-the-Hash](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack) attack using Windows Event Log Monitoring and remediate it, you would be able to find the compromised host very quickly and stop the lateral movement inside your network.

### _**Practical: The Pyramid of Pain**_
this is broken and won't complete. just click through.

### **Conclusion**
Now you have learned the concept of the Pyramid of Pain. Maybe it is time to apply this in practice. Please, navigate to the Static Site to perform the exercise.   

You can pick any APT (Advanced Persistent Threat Groups) as another exercise. A good place to look at would be [FireEye Advanced Persistent Threat Groups](https://www.fireeye.com/current-threats/apt-groups.html). When you have determined the APT Group you want to research - find their indicators and ask yourself: " What can I do or what detection rules and approach can I create to detect the adversary's activity?", and "Where does this activity or detection fall on the Pyramid of Pain?”

  

As David Blanco states, "_**the amount of pain you cause an adversary depends on the types of indicators you are able to make use of**_".

