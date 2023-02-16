# **Wireshark: The Basics**

## _**1: Introduction**_

Wireshark is an open-source, cross-platform network packet analyser tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools. In this room, we will look at the basics of Wireshark and use it to perform fundamental packet analysis.

There are two capture files given in the VM. You can use the "http1.pcapng" file to simulate the actions shown in the screenshots. Please note that you need to use the "Exercise.pcapng" file to answer the questions.

Which file is used to simulate the screenshots?

- http1.pcapng

Which file is used to answer the questions?

- Exercise.pcapng

## _**2: Tool Overview**_

**Use Cases**  

Wireshark is one of the most potent traffic analyser tools available in the wild. There are multiple purposes for its use:  

- Detecting and troubleshooting network problems, such as network load failure points and congestion.
- Detecting security anomalies, such as rogue hosts, abnormal port usage, and suspicious traffic.
- Investigating and learning protocol details, such as response codes and payload data. 

Note: Wireshark is not an Intrusion Detection System (IDS). It only allows analysts to discover and investigate the packets in depth. It also doesn't modify packets; it reads them. Hence, detecting any anomaly or network problem highly relies on the analyst's knowledge and investigation skills.

**GUI and Data**  

Wireshark GUI opens with a single all-in-one page, which helps users investigate the traffic in multiple ways. At first glance, five sections stand out.

|
|**Toolbar** | The main toolbar contains multiple menus and shortcuts for packet sniffing and processing, including filtering, sorting, summarising, exporting and merging. |
|**Display Filter Bar** | The main query and filtering section. |
|**Recent Files** | List of the recently investigated files. You can recall listed files with a double-click. |
|**Capture Filter and Interfaces** | Capture filters and available sniffing points (network interfaces).  The network interface is the connection point between a computer and a network. The software connection (e.g., lo, eth0 and ens33) enables networking hardware.|
|**Status Bar** | Tool status, profile and numeric packet information.|

The below picture shows Wireshark's main window. The sections explained in the table are highlighted. Now open the Wireshark and go through the walkthrough.

![](2023-02-03-05-20-27.png)

**Loading PCAP Files**  

The above picture shows Wireshark's empty interface. The only available information is the recently processed  "http1.cap" file. Let's load that file and see Wireshark's detailed packet presentation. Note that you can also use the **"File"** menu, dragging and dropping the file, or double-clicking on the file to load a pcap.

![](2023-02-03-05-21-37.png)

Now, we can see the processed filename, detailed number of packets and packet details. Packet details are shown in three different panes, which allow us to discover them in different formats. 

|
|Packet List Pane | Summary of each packet (source and destination addresses, protocol, and packet info). You can click on the list to choose a packet for further investigation. Once you select a packet, the details will appear in the other panels.  |
|Packet Details Pane | Detailed protocol breakdown of the selected packet. |
|Packet Bytes Pane |Hex and decoded ASCII representation of the selected packet. It highlights the packet field depending on the clicked section in the details pane. |

**Colouring Packets**

Along with quick packet information, Wireshark also colour packets in order of different conditions and the protocol to spot anomalies and protocols in captures quickly (this explains why almost everything is green in the given screenshots). This glance at packet information can help track down exactly what you're looking for during analysis. You can create custom colour rules to spot events of interest by using display filters, and we will cover them in the next room. Now let's focus on the defaults and understand how to view and use the represented data details.

Wireshark has two types of packet colouring methods: temporary rules that are only available during a program session and permanent rules that are saved under the preference file (profile) and available for the next program session. You can use the "right-click menu" or "View --> Coloring Rules" menu to create permanent colouring rules. The "Colourise Packet List" menu activates/deactivates the colouring rules. Temporary packet colouring is done with the "right-click menu" or "View --> Conversation Filter" menu, which is covered in TASK-5.

The default permanent colouring is shown below.

![](2023-02-03-05-24-26.png)

**Traffic Sniffing**

You can use the blue **"shark button"** to start network sniffing (capturing traffic), the red button will stop the sniffing, and the green button will restart the sniffing process. The status bar will also provide the used sniffing interface and the number of collected packets.

![](2023-02-03-05-25-17.png)

**Merge PCAP Files** 

Wireshark can combine two pcap files into one single file. You can use the **"File --> Merge"** menu path to merge a pcap with the processed one. When you choose the second file, Wireshark will show the total number of packets in the selected file. Once you click "open", it will merge the existing pcap file with the chosen one and create a new pcap file. Note that you need to save the "merged" pcap file before working on it.

**View File Details**

Knowing the file details is helpful. Especially when working with multiple pcap files, sometimes you will need to know and recall the file details (File hash, capture time, capture file comments, interface and statistics) to identify the file, classify and prioritise it. You can view the details by following "**Statistics --> Capture File Properties"** or by clicking the **"pcap icon located on the left bottom"** of the window.

**Questions**

Read the "capture file comments". What is the flag?

- located at the bottom of the "capture file properties" page
- TryHackMe_Wireshark_Demo

What is the total number of packets?

- located at the bottom right side of the window
- 58620

What is the SHA256 hash value of the capture file?

- located in the "File" section of the "capture file properties" page
- f446de335565fb0b0ee5e5a3266703c778b2f3dfad7efeaeccb2da5641a6d6eb

## _**3: Packet Dissection**_

Packet dissection is also known as protocol dissection, which investigates packet details by decoding available protocols and fields. Wireshark supports a long list of protocols for dissection, and you can also write your dissection scripts. You can find more details on dissection [**here**](https://github.com/boundary/wireshark/blob/master/doc/README.dissector).

**Note:** This section covers how Wireshark uses OSI layers to break down packets and how to use these layers for analysis. It is expected that you already have background knowledge of the OSI model and how it works. 

**Packet Details**

You can click on a packet in the packet list pane to open its details (double-click will open details in a new window). Packets consist of 5 to 7 layers based on the OSI model. We will go over all of them in an HTTP packet from a sample capture. The picture below shows viewing packet number 27.

![](2023-02-03-05-44-45.png)

Each time you click a detail, it will highlight the corresponding part in the packet bytes pane.

Let's have a closer view of the details pane.

![](2023-02-03-05-47-58.png)

We can see seven distinct layers to the packet: frame/packet, source [MAC], source [IP], protocol, protocol errors, application protocol, and application data. Below we will go over the layers in more detail.

The Frame (Layer 1): This will show you what frame/packet you are looking at and details specific to the Physical layer of the OSI model.

Source [MAC] (Layer 2): This will show you the source and destination MAC Addresses; from the Data Link layer of the OSI model.

Source [IP] (Layer 3): This will show you the source and destination IPv4 Addresses; from the Network layer of the OSI model.

Protocol (Layer 4): This will show you details of the protocol used (UDP/TCP) and source and destination ports; from the Transport layer of the OSI model.

Protocol Errors: This continuation of the 4th layer shows specific segments from TCP that needed to be reassembled.

Application Protocol (Layer 5): This will show details specific to the protocol used, such as HTTP, FTP,  and SMB. From the Application layer of the OSI model.

Application Data: This extension of the 5th layer can show the application-specific data.

**Questions**

View packet number 38. Which markup language is used under the HTTP protocol?

- The number column on the left side of the screen is the packet number
- eXtensible Markup Language

What is the arrival date of the packet? (Answer format: Month/Day/Year)

- Under the Frame section "Arrival Time"
- May 13, 2004
- 05/13/2004

What is the TTL value?

- Under the Internet Protocol section
- "Time to live"
- 47

What is the TCP payload size?

- Under the Transmission Control Protocol section
- "TCP payload"
- 424

What is the e-tag value?

- Under the Hypertext Transfer Protocol section
- "ETag"
- 9a01a-4696-7e354b00

## _**4: Packet Navigation**_

**Packet Numbers**

Wireshark calculates the number of investigated packets and assigns a unique number for each packet. This helps the analysis process for big captures and makes it easy to go back to a specific point of an event.

**Go to Packet**

Packet numbers do not only help to count the total number of packets or make it easier to find/investigate specific packets. This feature not only navigates between packets up and down; it also provides in-frame packet tracking and finds the next packet in the particular part of the conversation. You can use the **"Go"** menu and toolbar to view specific packets.

**Find Packets**

Apart from packet number, Wireshark can find packets by packet content. You can use the **"Edit --> Find Packet"** menu to make a search inside the packets for a particular event of interest. This helps analysts and administrators to find specific intrusion patterns or failure traces.

There are two crucial points in finding packets. The first is knowing the input type. This functionality accepts four types of inputs (Display filter, Hex, String and Regex). String and regex searches are the most commonly used search types. Searches are case insensitive, but you can set the case sensitivity in your search by clicking the radio button.

The second point is choosing the search field. You can conduct searches in the three panes (packet list, packet details, and packet bytes), and it is important to know the available information in each pane to find the event of interest. For example, if you try to find the information available in the packet details pane and conduct the search in the packet list pane, Wireshark won't find it even if it exists.

**Mark Packets**

Marking packets is another helpful functionality for analysts. You can find/point to a specific packet for further investigation by marking it. It helps analysts point to an event of interest or export particular packets from the capture. You can use the "Edit" or the "right-click" menu to mark/unmark packets.

Marked packets will be shown in black regardless of the original colour representing the connection type. Note that marked packet information is renewed every file session, so marked packets will be lost after closing the capture file.

![](2023-02-03-06-08-04.png)

**Packet Comments**

Similar to packet marking, commenting is another helpful feature for analysts. You can add comments for particular packets that will help to further the investigation or remind and point out important/suspicious points for other layer analysts. Unlike packet marking, the comments can stay within the capture file until the operator removes them.

**Export Packets**

Capture files can contain thousands of packets in a single file. As mentioned earlier, Wireshark is not an IDS, so sometimes, it is necessary to separate specific packages from the file and dig deeper to resolve an incident. This functionality helps analysts share only the suspicious packages (decided scope). Thus redundant information is not included in the analysis process. You can use the **"File"** menu to export packets.

**Export Objects (Files)**

Wireshark can extract files transferred through the wire. For a security analyst, it is vital to discover shared files and save them for further investigation. Exporting objects is available only for selected protocol's streams (DICOM, HTTP, IMF, SMB and TFTP).

**Time Display Format**

Wireshark lists the packets as they are captured, so investigating the default flow is not always the best option. By default, Wireshark shows the time in "Seconds Since Beginning of Capture", the common usage is using the UTC Time Display Format for a better view. You can use the "View --> Time Display Format" menu to change the time display format.

**Expert Info**

Wireshark also detects specific states of protocols to help analysts easily spot possible anomalies and problems. Note that these are only suggestions, and there is always a chance of having false positives/negatives. Expert info can provide a group of categories in three different severities. Details are shown in the table below.

![](2023-02-03-06-13-40.png)

Frequently encountered information groups are listed in the table below. You can refer to Wireshark's official documentation for more information on the expert information entries.

![](2023-02-03-06-14-21.png)

You can use the "lower left bottom section" in the status bar or "Analyse --> Expert Information" menu to view all available information entries via a dialogue box. It will show the packet number, summary, group protocol and total occurrence.

**Questions**

Search the "r4w" string in packet details. What is the name of artist 1?

- Edit -> Find Packet -> r4w
- I was looking for a name not the unique ID, just need to finish the string
- r4w8173

Go to packet 12 and read the comments. What is the answer?

- Go -> Go to packet -> 12 -> right click packet -> Packet comment -> scroll to bottom for more instructions
- Go to packet number 39765
Look at the "packet details pane". Right-click on the JPEG section and "Export packet bytes". This is an alternative way of extracting data from a capture file. What is the MD5 hash value of extracted image?
- Go -> Go to packet -> 39765 -> right click on JPEG section -> export packet bytes -> name file and save
- Open terminal -> `cd Desktop/` -> md5sum [filename] 
- 911cd574a42865a956ccde2d04495ebf

There is a ".txt" file inside the capture file. Find the file and read it; what is the alien's name?

- File -> Export Objects -> Text Filter: txt -> save -> open the file
- PACKETMASTER

Look at the expert info section. What is the number of warnings?

- Analyze -> Expert Information
- or red dot in the bottom left corner
- 1636

## _**5: Packet Filtering**_

Wireshark has a powerful filter engine that helps analysts to narrow down the traffic and focus on the event of interest. Wireshark has two types of filtering approaches: capture and display filters. Capture filters are used for **"capturing"** only the packets valid for the used filter. Display filters are used for **"viewing"** the packets valid for the used filter. We will discuss these filters' differences and advanced usage in the next room. Now let's focus on basic usage of the display filters, which will help analysts in the first place.

Filters are specific queries designed for protocols available in Wireshark's official protocol reference. While the filters are only the option to investigate the event of interest, there are two different ways to filter traffic and remove the noise from the capture file. The first one uses queries, and the second uses the right-click menu. Wireshark provides a powerful GUI, and there is a golden rule for analysts who don't want to write queries for basic tasks: _**"If you can click on it, you can filter and copy it"**_ .  
  
**Apply as Filter**

This is the most basic way of filtering traffic. While investigating a capture file, you can click on the field you want to filter and use the "right-click menu" or **"Analyse** **--> Apply as Filter"** menu to filter the specific value. Once you apply the filter, Wireshark will generate the required filter query, apply it, show the packets according to your choice, and hide the unselected packets from the packet list pane. Note that the number of total and displayed packets are always shown on the status bar.

**Conversation filter**

When you use the "Apply as a Filter" option, you will filter only a single entity of the packet. This option is a good way of investigating a particular value in packets. However, suppose you want to investigate a specific packet number and all linked packets by focusing on IP addresses and port numbers. In that case, the "Conversation Filter" option helps you view only the related packets and hide the rest of the packets easily. You can use the"right-click menu" or "**Analyse --> Conversation Filter**" menu to filter conversations.

**Colourise Conversation**

This option is similar to the "Conversation Filter" with one difference. It highlights the linked packets without applying a display filter and decreasing the number of viewed packets. This option works with the "Colouring Rules" option and changes the packet colours without considering the previously applied colour rule. You can use the "right-click menu" or **"View --> Colourise Conversation"** menu to colourise a linked packet in a single click. Note that you can use the "View --> Colourise Conversation --> Reset Colourisation" menu to undo this operation.

**Prepare as Filter**

Similar to "Apply as Filter", this option helps analysts create display filters using the "right-click" menu. However, unlike the previous one, this model doesn't apply the filters after the choice. It adds the required query to the pane and waits for the execution command (enter) or another chosen filtering option by using the **".. and/or.."** from the "right-click menu".

**Apply as Column**

By default, the packet list pane provides basic information about each packet. You can use the "right-click menu" or "Analyse **\-->**  Apply as Column" menu to add columns to the packet list pane. Once you click on a value and apply it as a column, it will be visible on the packet list pane. This function helps analysts examine the appearance of a specific value/field across the available packets in the capture file. You can enable/disable the columns shown in the packet list pane by clicking on the top of the packet list pane.

**Follow Stream**

Wireshark displays everything in packet portion size. However, it is possible to reconstruct the streams and view the raw traffic as it is presented at the application level. Following the protocol, streams help analysts recreate the application-level data and understand the event of interest. It is also possible to view the unencrypted protocol data like usernames, passwords and other transferred data.

You can use the"right-click menu" or  **"Analyse** **--> Follow TCP/UDP/HTTP Stream"** menu to follow traffic streams. Streams are shown in a separate dialogue box; packets originating from the server are highlighted with blue, and those originating from the client are highlighted with red.

Once you follow a stream, Wireshark automatically creates and applies the required filter to view the specific stream. Remember, once a filter is applied, the number of the viewed packets will change. You will need to use the "**X** **button**" located on the right upper side of the display filter bar to remove the display filter and view all available packets in the capture file.

**Questions**

Go to packet number 4. Right-click on the "Hypertext Transfer Protocol" and apply it as a filter. Now, look at the filter pane. What is the filter query?

- right click apply filter -> selected
- http

What is the number of displayed packets?

- look at the bottom right of the window
- 1089

Go to packet number 33790 and follow the stream. What is the total number of artists?

- Go -> Go to packet -> 33790
- right click follow stream -> http stream -> Find: artist=
- 3
- it might be easier to export the php file
- File -> export objects -> http -> Text Filter: php -> artists.php -> save
- right click file -> open with pluma -> search for artist= -> hi-lights all of them (only 3 in the file)
- 3

What is the name of the second artist?

- on the same PHP file look for "artist=2"
- `artist=2'><h3>Blad3</h3>`
- Blad3
- or right click follow stream -> http stream -> Find: artist=2
- `artist=2'><h3>Blad3</h3>`
- Blad3

# **Wireshark: Packet Operations**

## _**1: Introduction**_

In this room, we will cover the fundamentals of packet analysis with Wireshark and investigate the event of interest at the packet-level. Note that this is the second room of the Wireshark room trio, and it is suggested to visit the first room ([**Wireshark: The Basics**](https://tryhackme.com/room/wiresharkthebasics)) to practice and refresh your Wireshark skills before starting this one.

In the first room, we covered the basics of Wireshark by focusing on how it operates and how to use it to investigate traffic captures. In this room, we will cover advanced features of Wireshark by focusing on packet-level details with Wireshark statistics, filters, operators and functions.

## _**2: Statistics | Summary**_

**Statistics**

This menu provides multiple statistics options ready to investigate to help users see the big picture in terms of the scope of the traffic, available protocols, endpoints and conversations, and some protocol-specific details like DHCP, DNS and HTTP/2. For a security analyst, it is crucial to know how to utilise the statical information. This section provides a quick summary of the processed pcap, which will help analysts create a hypothesis for an investigation. You can use the **"Statistics"** menu to view all available options. Now start the given VM, open the Wireshark, load the "Exercise.pcapng" file and go through the walkthrough.

**Resolved Addresses**

This option helps analysts identify IP addresses and DNS names available in the capture file by providing the list of the resolved addresses and their hostnames. Note that the hostname information is taken from DNS answers in the capture file. Analysts can quickly identify the accessed resources by using this menu. Thus they can spot accessed resources and evaluate them according to the event of interest. You can use the **"Statistics --> Resolved Addresses"** menu to view all resolved addresses by Wireshark.

**Protocol Hierarchy**

This option breaks down all available protocols from the capture file and helps analysts view the protocols in a tree view based on packet counters and percentages. Thus analysts can view the overall usage of the ports and services and focus on the event of interest. The golden rule mentioned in the previous room is valid in this section; you can right-click and filter the event of interest. You can use the **"Statistics --> Protocol Hierarchy"** menu to view this info.

**Conversations**

Conversation represents traffic between two specific endpoints. This option provides the list of the conversations in five base formats; ethernet, IPv4, IPv6, TCP and UDP. Thus analysts can identify all conversations and contact endpoints for the event of interest. You can use the **"Statistic --> Conversations"** menu to view this info.

Endpoints

The endpoints option is similar to the conversations option. The only difference is that this option provides unique information for a single information field (Ethernet, IPv4, IPv6, TCP and UDP ). Thus analysts can identify the unique endpoints in the capture file and use it for the event of interest. You can use the **"Statistics --> Endpoints"** menu to view this info.

Wireshark also supports resolving MAC addresses to human-readable format using the manufacturer name assigned by IEEE. Note that this conversion is done through the first three bytes of the MAC address and only works for the known manufacturers. When you review the ethernet endpoints, you can activate this option with the **"Name resolution"** button in the lower-left corner of the endpoints window.

Name resolution is not limited only to MAC addresses. Wireshark provides IP and port name resolution options as well. However, these options are not enabled by default. If you want to use these functionalities, you need to activate them through the **"Edit --> Preferences --> Name Resolution"** menu. Once you enable IP and port name resolution, you will see the resolved IP address and port names in the packet list pane and also will be able to view resolved names in the "Conversations" and "Endpoints" menus as well.

Besides name resolution, Wireshark also provides an IP geolocation mapping that helps analysts identify the map's source and destination addresses. But this feature is not activated by default and needs supplementary data like the GeoIP database. Currently, Wireshark supports MaxMind databases, and the latest versions of the Wireshark come configured MaxMind DB resolver. However, you still need MaxMind DB files and provide the database path to Wireshark by using the **"Edit --> Preferences --> Name Resolution --> MaxMind database directories"** menu. Once you download and indicate the path, Wireshark will automatically provide GeoIP information under the IP protocol details for the matched IP addresses.

Endpoints and GeoIP view.

![](2023-02-06-06-49-03.png)

**Note:** You need an active internet connection to view the GeoIP map.

**Questions**

Investigate the resolved addresses. What is the IP address of the hostname starts with "bbc"?

- open Wireshark
- File -> Open -> Exercise.pcapng
- Statistics -> Resolved Addresses
- Search for entry (min 3 characters) -> bbc
- 199.232.24.81

What is the number of IPv4 conversations?

- Statistics -> Conversations -> IPv4 tab
- 435

How many bytes (k) were transferred from the "Micro-St" MAC address?

- Statistics -> Endpoints -> Name resolution
- Micro-St 9a:f1:f5 -> Tx Bytes column
- 1083
- Try Hack Me wants the Total Bytes
- Micro-St 9a:f1:f5 -> Bytes column
- 7474

What is the number of IP addresses linked with "Kansas City"?

- Statistics -> Endpoints -> Name resolution
- IPv4 tab -> City column -> Kansas City
- 4

Which IP address is linked with "Blicnet" AS Organisation?

- Statistics -> Endpoints
- IPv4 tab -> AS Organization column -> double click column name to sort -> hi-light Blicnet d.o.o.
- 188.246.82.7

## _**3: Statistics | Protocol Details**_

**IPv4 and IPv6**

Up to here, almost all options provided information that contained both versions of the IP addresses. The statistics menu has two options for narrowing the statistics on packets containing a specific IP version. Thus, analysts can identify and list all events linked to specific IP versions in a single window and use it for the event of interest. You can use the **"Statistics --> IPvX Statistics"** menu to view this info.

**DNS**

This option breaks down all DNS packets from the capture file and helps analysts view the findings in a tree view based on packet counters and percentages of the DNS protocol. Thus analysts can view the DNS service's overall usage, including rcode, opcode, class, query type, service and query stats and use it for the event of interest. You can use the **"Statistics --> DNS"** menu to view this info.

**HTTP**

This option breaks down all HTTP packets from the capture file and helps analysts view the findings in a tree view based on packet counters and percentages of the HTTP protocol. Thus analysts can view the HTTP service's overall usage, including request and response codes and the original requests. You can use the **"Statistics --> HTTP"** menu to view this info.

**Questions**

What is the most used IPv4 destination address?

- Open Wireshark
- Open file Exercise.pcapng on desktop
- Statistics -> IPv4 Statistics -> Destinations and Ports -> double click Count column to sort
- 10.100.1.33 with 29387

What is the max service request-response time of the DNS packets?

- Statistics -> DNS -> On the Topic/Item column look for Service Stats -> expand and look for request-response time (secs) and hi-light it -> look at the Max val column
- 0.467897

What is the number of HTTP Requests accomplished by "rad[.]msn[.]com?

- Statistics -> HTTP -> Requests -> look under Topic/Item for the above web site and hi-light it -> scroll right to Count column
- 39

## _**4: Packet Filtering | Principles**_

In the previous room ([**Wireshark | The Basics**](https://tryhackme.com/room/wiresharkthebasics)), we covered packet filtering and how to filter packets without using queries. In this room, we will use queries to filter packets. As mentioned earlier, there are two types of filters in Wireshark. While both use similar syntax, they are used for different purposes. Let's remember the difference between these two categories.  

|
|Capture Filters|This type of filter is used to save only a specific part of the traffic. It is set before capturing traffic and not changeable during the capture.|
|Display Filters|This type of filter is used to investigate packets by reducing the number of visible packets, and it is changeable during the capture.|

**Note:** You cannot use the display filter expressions for capturing traffic and vice versa.

The typical use case is capturing everything and filtering the packets according to the event of interest. Only experienced professionals use capture filters and sniff traffic. This is why Wireshark supports more protocol types in display filters. Please ensure you thoroughly learn how to use capture filters before using them in a live environment. Remember, you cannot capture the event of interest if your capture filter is not matching the specific traffic pattern you are looking for.  
  

**Capture Filter Syntax**

These filters use byte offsets hex values and masks with boolean operators, and it is not easy to understand/predict the filter's purpose at first glance. The base syntax is explained below:  

- Scope: host, net, port and portrange.
- Direction: src, dst, src or dst, src and dst,
- Protocol: ether, wlan, ip, ip6, arp, rarp, tcp and udp.
- Sample filter to capture port 80 traffic: `tcp port 80`  
    

You can read more on capture filter syntax from [here](https://www.wireshark.org/docs/man-pages/pcap-filter.html) and [here](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureFilters#useful-filters). A quick reference is available under the **"Capture --> Capture Filters"** menu.

**Display Filter Syntax**

This is Wireshark's most powerful feature. It supports 3000 protocols and allows conducting packet-level searches under the protocol breakdown. The official "[Display Filter Reference](https://www.wireshark.org/docs/dfref/)" provides all supported protocols breakdown for filtering.

- Sample filter to capture port 80 traffic: `tcp.port == 80`  

Wireshark has a built-in option (Display Filter Expression) that stores all supported protocol structures to help analysts create display filters. We will cover the "Display Filter Expression" menu later. Now let's understand the fundamentals of the display filter operations. A quick reference is available under the **"Analyse --> Display Filters"** menu.

**Comparison Operators**

You can create display filters by using different comparison operators to find the event of interest. The primary operators are shown in the table below.

<table class="table table-bordered"><tbody><tr><td><b>English</b></td><td><b>C-Like</b></td><td><b>Description</b></td><td><b>Example</b></td></tr><tr><td>eq</td><td>==</td><td>Equal</td><td><p><code>ip.src == 10.10.10.100</code></p></td></tr><tr><td>ne</td><td>!=</td><td>Not equal</td><td><p><code>ip.src != 10.10.10.100</code></p></td></tr><tr><td>gt</td><td>&gt;</td><td>Greater than</td><td><p><code>ip.ttl &gt; 250</code></p></td></tr><tr><td>lt</td><td>&lt;</td><td>Less Than</td><td><p><code>ip.ttl &lt; 10</code><br></p></td></tr><tr><td>ge</td><td>&gt;=</td><td>Greater than or equal to</td><td><p><code>ip.ttl &gt;= 0xFA</code></p></td></tr><tr><td>le</td><td>&lt;=</td><td>Less than or equal to</td><td><p><code>ip.ttl &lt;= 0xA</code></p></td></tr></tbody></table>

**Note:** Wireshark supports decimal and hexadecimal values in filtering. You can use any format you want according to the search you will conduct.

**Logical Expressions**

Wireshark supports boolean syntax. You can create display filters by using logical operators as well.

<table class="table table-bordered"><tbody><tr><td><b>English&nbsp;&nbsp;</b></td><td><b>C-Like</b></td><td><b>Description&nbsp;&nbsp;</b></td><td><b>Example</b></td></tr><tr><td>and</td><td>&amp;&amp;</td><td>Logical AND</td><td><p><code>(ip.src == 10.10.10.100) AND (ip.src == 10.10.10.111)</code></p></td></tr><tr><td>or</td><td>||</td><td>Logical OR</td><td><p><code>(ip.src == 10.10.10.100) OR (ip.src == 10.10.10.111)</code></p></td></tr><tr><td>not</td><td>!</td><td>Logical NOT</td><td><p><code>!(ip.src == 10.10.10.222)</code></p><p style="text-align:left"><b>Note:</b>&nbsp;Usage of <code>!=value</code>&nbsp;is deprecated; using it could provide inconsistent results. Using the <code>!(value)</code><b></b>&nbsp;style is suggested for more consistent results.</p></td></tr></tbody></table> 

**Note:** Usage of `!=value` is deprecated; using it could provide inconsistent results. Using the `!(value)` style is suggested for more consistent results.

**Packet Filter Toolbar**

The filter toolbar is where you create and apply your display filters. It is a smart toolbar that helps you create valid display filters with ease. Before starting to filter packets, here are a few tips:  

- Packet filters are defined in lowercase.
- Packet filters have an autocomplete feature to break down protocol details, and each detail is represented by a "dot".
- Packet filters have a three-colour representation explained below.

![](2023-02-15-06-50-01.png)

Filter toolbar features are shown below.

![](2023-02-15-06-52-03.png)

## _**5: Packet Filtering | Protocol Filters**_

**Protocol Filters**

As mentioned in the previous task, Wireshark supports 3000 protocols and allows packet-level investigation by filtering the protocol fields. This task shows the creation and usage of filters against different protocol fields. 

**IP Filters**

IP filters help analysts filter the traffic according to the IP level information from the packets (Network layer of the OSI model). This is one of the most commonly used filters in Wireshark. These filters filter network-level information like IP addresses, version, time to live, type of service, flags, and checksum values.

The common filters are shown in the given table.

<table class="table table-bordered" style="width:1075px"><tbody><tr><td><span style="font-weight:bolder">Filter</span></td><td><span style="font-weight:bolder">Description</span></td></tr><tr><td><p><code style="font-size:14px">ip</code></p></td><td style="text-align:left">Show all IP packets.</td></tr><tr><td><p><code style="font-size:14px">ip.addr == 10.10.10.111</code></p></td><td style="text-align:left">Show all packets containing IP address 10.10.10.111.</td></tr><tr><td><p><code style="font-size:14px">ip.addr == 10.10.10.0/24</code></p></td><td style="text-align:left">Show all packets containing IP addresses from 10.10.10.0/24 subnet.</td></tr><tr><td><p><code style="font-size:14px">ip.src == 10.10.10.111</code></p></td><td style="text-align:left">Show all packets originated from 10.10.10.111</td></tr><tr><td><p><code style="font-size:14px">ip.dst == 10.10.10.111</code></p></td><td style="text-align:left">Show all packets sent to 10.10.10.111</td></tr><tr><td>ip.addr<span style="font-weight:bolder">&nbsp;vs&nbsp;</span>ip.src/ip.dst</td><td style="text-align:left"><span style="font-weight:bolder">Note:&nbsp;</span>The ip.addr filters the traffic without considering the packet direction. The ip.src/ip.dst filters the packet depending on the packet direction.</td></tr></tbody></table>

**TCP and UDP Filters**

TCP filters help analysts filter the traffic according to protocol-level information from the packets (Transport layer of the OSI model). These filters filter transport protocol level information like source and destination ports, sequence number, acknowledgement number, windows size, timestamps, flags, length and protocol errors.

<table class="table table-bordered" style="width:1075px"><tbody><tr><td><span style="font-weight:700">Filter</span><br></td><td><span style="font-weight:700">Description</span><br></td><td><span style="font-weight:bolder">Filter</span></td><td><span style="font-weight:bolder">Expression</span></td></tr><tr><td><p><code style="font-size:14px">tcp.port == 80</code></p></td><td style="text-align:left"><span>Show all <a class="abpUH7Hi glossary-term" onclick="initPopOver('TCP', 'abpUH7Hi')" href="">TCP</a> packets with port 80&nbsp;</span></td><td><p><code style="font-size:14px">udp.port == 53</code><br></p></td><td style="text-align:left"><span>Show all <a class="Ra5uVuWI glossary-term" onclick="initPopOver('UDP', 'Ra5uVuWI')" href="">UDP</a> packets with port 53</span></td></tr><tr><td><p><code style="font-size:14px">tcp.srcport == 1234</code></p></td><td style="text-align:left"><span>Show all <a class="3ry0shFU glossary-term" onclick="initPopOver('TCP', '3ry0shFU')" href="">TCP</a> packets originating from port 1234</span></td><td><p><code style="font-size:14px">udp.srcport == 1234</code><br></p></td><td style="text-align:left"><span>Show all <a class="TECyYkn5 glossary-term" onclick="initPopOver('UDP', 'TECyYkn5')" href="">UDP</a> packets originating from port 1234</span></td></tr><tr><td><p><code style="font-size:14px">tcp.dstport == 80</code></p></td><td style="text-align:left"><span>Show all <a class="fJxKiHm9 glossary-term" onclick="initPopOver('TCP', 'fJxKiHm9')" href="">TCP</a> packets sent to port 80</span></td><td><p><code style="font-size:14px">udp.dstport == 5353</code><br></p></td><td style="text-align:left"><span>Show all <a class="TFgdUnow glossary-term" onclick="initPopOver('UDP', 'TFgdUnow')" href="">UDP</a> packets sent to port 5353</span></td></tr></tbody></table>

**Application Level Protocol Filters | HTTP and DNS**

Application-level protocol filters help analysts filter the traffic according to application protocol level information from the packets (Application layer of the OSI model ). These filters filter application-specific information, like payload and linked data, depending on the protocol type.

<table class="table table-bordered" style="width:1075px"><tbody><tr><td><span style="font-weight:bolder">Filter</span></td><td><span style="font-weight:bolder">Description</span></td><td><span style="font-weight:bolder">Filter</span></td><td><span style="font-weight:bolder">Description</span></td></tr><tr><td><p><code style="font-size:14px">http</code></p></td><td><span>Show all <a class="eNzu48rH glossary-term" onclick="initPopOver('HTTP', 'eNzu48rH')" href="">HTTP</a> packets</span></td><td><p><code style="font-size:14px">dns</code></p></td><td><span>Show all <a class="fUc1Jt3v glossary-term" onclick="initPopOver('DNS', 'fUc1Jt3v')" href="">DNS</a> packets</span></td></tr><tr><td><p><code style="font-size:14px">http.response.code == 200</code></p></td><td><span>Show all packets with <a class="hQfaeiyX glossary-term" onclick="initPopOver('HTTP', 'hQfaeiyX')" href="">HTTP</a> response code "200"</span></td><td><p><code style="font-size:14px">dns.flags.response == 0</code><br></p></td><td><span>Show all <a class="IAFnV9dO glossary-term" onclick="initPopOver('DNS', 'IAFnV9dO')" href="">DNS</a> requests</span></td></tr><tr><td><p><code style="font-size:14px">http.request.method == "GET"</code></p></td><td><span>Show all <a class="G4fHoeAd glossary-term" onclick="initPopOver('HTTP', 'G4fHoeAd')" href="">HTTP</a> GET requests</span></td><td><p><code style="font-size:14px">dns.flags.response == 1</code><br></p></td><td><span>Show all <a class="7E5Esef1 glossary-term" onclick="initPopOver('DNS', '7E5Esef1')" href="">DNS</a> responses</span></td></tr><tr><td><p><code style="font-size:14px">http.request.method == "POST"</code><br></p></td><td><span>Show all <a class="Mfgt8Ego glossary-term" onclick="initPopOver('HTTP', 'Mfgt8Ego')" href="">HTTP</a> POST requests</span></td><td><p><code style="font-size:14px">dns.qry.type == 1</code><br></p></td><td><span>Show all <a class="4VmtI1sk glossary-term" onclick="initPopOver('DNS', '4VmtI1sk')" href="">DNS</a> "A" records</span></td></tr></tbody></table>

**Display Filter Expressions**

As mentioned earlier, Wireshark has a built-in option (Display Filter Expression) that stores all supported protocol structures to help analysts create display filters. When an analyst can't recall the required filter for a specific protocol or is unsure about the assignable values for a filter, the Display Filter Expressions menu provides an easy-to-use display filter builder guide. It is available under the **"Analyse --> Display Filter Expression"** menu.

It is impossible to memorise all details of the display filters for each protocol. Each protocol can have different fields and can accept various types of values. The Display Filter Expressions menu shows all protocol fields, accepted value types (integer or string) and predefined values (if any). Note that it will take time and require practice to master creating filters and learning the protocol filter fields.

Note: The [first room](https://tryhackme.com/room/wiresharkthebasics) introduced the "Colouring Rules" (Task-2). Now you know how to create display filters and filter the event of interest. You can use the **"View --> Coloring Rules"** menu to assign colours to highlight your display filter results.

**Questions**

What is the number of IP packets?

- Start Wireshark
- Open Exercise.pcapng
- Apply Display filter of `ip`
- Bottom right side of window look for Packets then Displayed
- 81420

What is the number of packets with a "TTL value less than 10"?

- Apply Display filter of `ip.ttl < 10`
- Bottom right side of window look for Packets then Displayed
- 66

What is the number of packets which uses "TCP port 4444"?

- Apply Display filter of `tcp.port == 4444`
- Bottom right side of window look for Packets then Displayed
- 632


What is the number of "HTTP GET" requests sent to port "80"?

- Apply Display filter of `(tcp.port == 80) && (http.request.method == "GET")`
- Bottom right side of window look for Packets then Displayed
- 527

What is the number of "type A DNS Queries"?

- Apply Display filter of `(dns.flags.response == 0) && (dns.qry.type == 1)`
- Bottom right side of window look for Packets then Displayed
- 55
- This didn't give the right answer. You can see under the Protocol column some are LLMNR
- `((dns.flags.response == 0) && (dns.qry.type == 1)) && !(llmnr)`
- 51
- Or you can do the following
- Go to Statistics -> DNS
- Under Total Packets -> Query Type -> A (Host Address)
- Hi-lite A (Host Address) -> Display filter: `dns.flags.response==0` -> Apply
- Look at A (Host Address) Count Column
- 51
- An even easier filter is 
- `dns.a`

## **6: Advanced Filtering**

So far, you have learned the basics of packet filtering operations. Now it is time to focus on specific packet details for the event of interest. Besides the operators and expressions covered in the previous room, Wireshark has advanced operators and functions. These advanced filtering options help the analyst conduct an in-depth analysis of an event of interest.  

**Filter: "contains"**

<table class="table table-bordered"><tbody><tr><td style="text-align:center"><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>contains</b></span><br></td></tr><tr><td style="text-align:center"><b>Type</b></td><td style="text-align:left"><span style="text-align:center">Comparison Operator</span><br></td></tr><tr><td style="text-align:center"><b>Description</b></td><td style="text-align:left">Search a value inside packets. It is case-sensitive and provides similar functionality to the "Find" option by focusing on a specific field.<br></td></tr><tr><td style="text-align:center"><b>Example</b></td><td style="text-align:left">Find all "Apache" servers.<br></td></tr><tr><td style="text-align:center"><b>Workflow</b></td><td style="text-align:left"><span>List all <a class="MnOJgyHX glossary-term" onclick="initPopOver('HTTP', 'MnOJgyHX')" href="">HTTP</a> packets where packets' "server" field contains the "Apache" keyword.</span><br></td></tr><tr><td style="text-align:center"><b>Usage</b></td><td><p style="text-align:left"><code>http.server contains "Apache"</code></p></td></tr></tbody></table>

**Filter: "matches"**

<table class="table table-bordered" style="width:1075.56px"><tbody><tr><td><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>matches</b></span><br></td></tr><tr><td><span style="font-weight:bolder">Type</span></td><td style="text-align:left"><span style="text-align:center">Comparison Operator</span><br></td></tr><tr><td><span style="font-weight:bolder">Description</span></td><td style="text-align:left">Search a pattern of a regular expression. It is case insensitive, and complex queries have a margin of error.<br></td></tr><tr><td><b>Example</b></td><td style="text-align:left">Find all .php and .html pages.<br></td></tr><tr><td><span style="font-weight:bolder">Workflow</span></td><td style="text-align:left">List all&nbsp;<a class="piGtAY8A glossary-term" href="">HTTP</a>&nbsp;packets where packets' "host" fields match keywords ".php" or ".html".<br></td></tr><tr><td><b>Usage</b></td><td style="text-align:left"><p><code>http.host matches "\.(php|html)"</code></p></td></tr></tbody></table>

**Filter: "in"**

<table class="table table-bordered" style="width:1075.56px"><tbody><tr><td><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>in</b></span><br></td></tr><tr><td><span style="font-weight:bolder">Type</span></td><td style="text-align:left"><span style="text-align:center">&nbsp;Set Membership</span><br></td></tr><tr><td><span style="font-weight:bolder">Description</span></td><td style="text-align:left">Search a value or field inside of a specific scope/range.<br></td></tr><tr><td><span style="font-weight:bolder">Example</span></td><td style="text-align:left">Find all packets that use ports 80, 443 or 8080.<br></td></tr><tr><td><span style="font-weight:bolder">Workflow</span></td><td style="text-align:left"><span>List all <a class="MOSoT23R glossary-term" onclick="initPopOver('TCP', 'MOSoT23R')" href="">TCP</a> packets where packets' "port" fields have values 80, 443 or 8080.</span><br></td></tr><tr><td><span style="font-weight:bolder">Usage</span></td><td style="text-align:left"><p><code>tcp.port in {80 443 8080}</code></p></td></tr></tbody></table>

**Filter: "upper"**

<table class="table table-bordered" style="width:1075.56px"><tbody><tr><td><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>upper</b></span><br></td></tr><tr><td><span style="font-weight:bolder">Type</span></td><td style="text-align:left"><span style="text-align:center">Function</span><br></td></tr><tr><td><span style="font-weight:bolder">Description</span></td><td style="text-align:left">Convert a string value to uppercase.<br></td></tr><tr><td><span style="font-weight:bolder">Example</span></td><td style="text-align:left">Find all "APACHE" servers.<br></td></tr><tr><td><span style="font-weight:bolder">Workflow</span></td><td style="text-align:left">Convert all&nbsp;<a class="Y3FkDOGg glossary-term" href="">HTTP</a>&nbsp;packets' "server" fields to uppercase and list packets that contain the "APACHE" keyword.<br></td></tr><tr><td><span style="font-weight:bolder">Usage</span></td><td style="text-align:left"><p><code>upper(http.server) contains "APACHE"</code></p></td></tr></tbody></table>

**Filter: "lower"**

<table class="table table-bordered" style="width:1075.56px"><tbody><tr><td><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>lower</b></span><br></td></tr><tr><td><span style="font-weight:bolder">Type</span></td><td style="text-align:left"><span style="text-align:center">Function</span><br></td></tr><tr><td><span style="font-weight:bolder">Description</span></td><td style="text-align:left">Convert a string value to lowercase.<br></td></tr><tr><td><span style="font-weight:bolder">Example</span></td><td style="text-align:left">Find all "apache" servers.<br></td></tr><tr><td><span style="font-weight:bolder">Workflow</span></td><td style="text-align:left">Convert all&nbsp;<a class="Q3BlQNOG glossary-term" href="">HTTP</a>&nbsp;packets' "server" fields info to lowercase and list packets that contain the "apache" keyword.<br></td></tr><tr><td><b>Usage</b></td><td style="text-align:left"><p><code>lower(http.server) contains "apache"</code></p></td></tr></tbody></table>

**Filter: "string"**

<table class="table table-bordered" style="width:1075.56px"><tbody><tr><td><span style="font-weight:bolder">Filter</span><br></td><td style="text-align:left"><span style="text-align:center"><b>string</b></span><br></td></tr><tr><td><span style="font-weight:bolder">Type</span></td><td style="text-align:left"><span style="text-align:center">Function</span><br></td></tr><tr><td><span style="font-weight:bolder">Description</span></td><td style="text-align:left">Convert a non-string value to a string.<br></td></tr><tr><td><span style="font-weight:bolder">Example</span></td><td style="text-align:left">Find all frames with odd numbers.<br></td></tr><tr><td><span style="font-weight:bolder">Workflow</span></td><td style="text-align:left">Convert all "frame number" fields to string values, and list frames end with odd values.<br></td></tr><tr><td><span style="font-weight:bolder">Usage</span></td><td style="text-align:left"><p><code>string(frame.number) matches "[13579]$"</code></p></td></tr></tbody></table>

**Bookmarks and Filtering Buttons**

We've covered different types of filtering options, operators and functions. It is time to create filters and save them as bookmarks and buttons for later usage. As mentioned in the previous task, the filter toolbar has a filter bookmark section to save user-created filters, which helps analysts re-use favourite/complex filters with a couple of clicks. Similar to bookmarks, you can create filter buttons ready to apply with a single click. 

Creating and using bookmarks.

![](2023-02-15-09-43-33.png)

Creating and using display filter buttons.

![](2023-02-15-09-44-11.png)

**Profiles**

Wireshark is a multifunctional tool that helps analysts to accomplish in-depth packet analysis. As we covered during the room, multiple preferences need to be configured to analyse a specific event of interest. It is cumbersome to re-change the configuration for each investigation case, which requires a different set of colouring rules and filtering buttons. This is where Wireshark profiles come into play. You can create multiple profiles for different investigation cases and use them accordingly. You can use the **"Edit --> Configuration Profiles"** menu or the **"lower right bottom of the status bar --> Profile"** section to create, modify and change the profile configuration.

**Questions**

Find all Microsoft IIS servers. What is the number of packets that did not originate from "port 80"?

- Start Wireshark
- Open Exercise.pcapng from desktop
- Display filter
- `(http.server contains "Microsoft-IIS") && !(tcp.srcport == 80)`
- 21

Find all Microsoft IIS servers. What is the number of packets that have "version 7.5"?

- `(http.server contains "Microsoft-IIS/7.5")`
- 71

What is the total number of packets that use ports 3333, 4444 or 9999?

- `tcp.port in { 3333 4444 9999}`
- 2235

What is the number of packets with "even TTL numbers"?

- `string (ip.ttl) matches "[24680]$"`
- 77289

Change the profile to "Checksum Control". What is the number of "Bad TCP Checksum" packets?

- `tcp.checksum.status == "Bad"`
- 34185

Use the existing filtering button to filter the traffic. What is the number of displayed packets?

- Look to the right of the Display filter bar for `gif/jpeg with http-200` and click that
- The applied filter is 
- `(http.response.code == 200 ) && (http.content_type matches "image(gif||jpeg)")`
- 261

# **Wireshark: Traffic Analysis**

## _**1: Introduction**_
In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities. Note that this is the third and last room of the Wireshark room trio, and it is suggested to visit the first two rooms stated below to practice and refresh your Wireshark skills before starting this one.

- [**Wireshark: The Basics**](https://tryhackme.com/room/wiresharkthebasics)
- [**Wireshark: Packet Operations**](https://tryhackme.com/room/wiresharkpacketoperations)

In the first two rooms, we have covered how to use Wireshark and do packet-level searches. Now, it is time to investigate and correlate the packet-level information to see the big picture in the network traffic, like detecting anomalies and malicious activities. For a security analyst, it is vital to stop and understand pieces of information spread in packets by applying the analyst's knowledge and tool functionality. This room will cover investigating packet-level details by synthesising the analyst knowledge and  Wireshark functionality for detecting anomalies and odd situations for a given case.

## _**2: Nmap Scans**_

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

- TCP connect scans
- SYN scans
- UDP scans

It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network. 

**TCP flags in a nutshell.**

<table class="table table-bordered"><tbody><tr><td><b>Notes</b></td><td><b>Wireshark Filters</b></td></tr><tr><td>Global search.</td><td><ul><li style="text-align:left"><code>tcp</code></li></ul><ul><li style="text-align:left"><code>udp</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only SYN flag.</li><li style="text-align:left">SYN flag is set. The rest of the bits are not important.</li></ul></td><td><ul><li style="text-align:left"><code>tcp.flags == 2</code></li></ul><ul><li style="text-align:left"><code>tcp.flags.syn == 1</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only ACK flag.</li><li style="text-align:left">ACK flag is set. The rest of the bits are not important.<br></li></ul></td><td><ul><li style="text-align:left"><code>tcp.flags == 16</code></li></ul><ul><li style="text-align:left"><code>tcp.flags.ack == 1</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only SYN, ACK flags.</li><li style="text-align:left">SYN and ACK are set. The rest of the bits are not important.</li></ul></td><td><ul><li style="text-align:left"><code>tcp.flags == 18</code></li></ul><ul><li style="text-align:left"><code>(tcp.flags.syn == 1) and (tcp.flags.ack == 1)</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only RST flag.</li><li style="text-align:left">RST flag is set. The rest of the bits are not important.<br></li></ul></td><td><div style="text-align:left"><br></div><ul><li style="text-align:left"><code>tcp.flags == 4</code></li></ul><ul><li style="text-align:left"><code>tcp.flags.reset == 1</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only RST, ACK flags.</li><li style="text-align:left">RST and ACK are set. The rest of the bits are not important.<br></li></ul></td><td><ul><li style="text-align:left"><code>tcp.flags == 20</code></li></ul><ul><li style="text-align:left"><code>(tcp.flags.reset == 1) and (tcp.flags.ack == 1)</code></li></ul></td></tr><tr><td><ul><li style="text-align:left">Only FIN flag</li><li style="text-align:left">FIN flag is set. The rest of the bits are not important.</li></ul></td><td><ul><li style="text-align:left"><code style="font-size:14px">tcp.flags == 1</code></li></ul><ul><li style="text-align:left"><code style="font-size:14px">tcp.flags.fin == 1</code></li></ul></td></tr></tbody></table>

TCP Connect Scans  

**TCP Connect Scan in a nutshell:**

- Relies on the three-way handshake (needs to finish the handshake process).
- Usually conducted with `nmap -sT` command.
- Used by non-privileged users (only option for a non-root user).
- Usually has a windows size larger than 1024 bytes as the request expects some data due to the nature of the protocol.

<table class="table table-bordered"><tbody><tr><td><b><span>Open TCP Port</span></b></td><td><b><span>Open TCP Port</span><br></b></td><td><b><span>Closed TCP Port</span></b><br></td></tr><tr><td><ul><li style="text-align:left">SYN --&gt;</li><li style="text-align:left">&lt;-- SYN, ACK</li><li style="text-align:left">ACK --&gt;<br></li></ul></td><td><ul><li style="text-align:left"><span style="text-align:center">SYN --&gt;</span></li><li style="text-align:left"><span style="text-align:center">&lt;-- SYN, ACK</span></li><li style="text-align:left"><span style="text-align:center">ACK --&gt;</span></li><li style="text-align:left"><span style="text-align:center">RST, ACK --&gt;</span><br></li></ul></td><td><ul><li style="text-align:left"><span style="text-align:center">SYN --&gt;</span></li><li style="text-align:left"><span style="text-align:center">&lt;-- RST, ACK</span><br></li></ul></td></tr></tbody></table>

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case's details.

Open TCP port (Connect):

![](2023-02-15-12-48-00.png)

Closed TCP port (Connect):

![](2023-02-15-12-48-24.png)

The above images provide the patterns in isolated traffic. However, it is not always easy to spot the given patterns in big capture files. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point. The given filter shows the TCP Connect scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`

**SYN Scans**  

TCP SYN Scan in a nutshell:

- Doesn't rely on the three-way handshake (no need to finish the handshake process).
- Usually conducted with `nmap -sS` command.
- Used by privileged users.
- Usually have a size less than or equal to 1024 bytes as the request is not finished and it doesn't expect to receive data.

<table class="table table-bordered"><tbody><tr><td><b><span>Open TCP Port</span></b></td><td><b><span>Close TCP Port</span></b></td></tr><tr><td><ul><li style="text-align:left">SYN --&gt;</li><li style="text-align:left">&lt;-- SYN,ACK</li><li style="text-align:left">RST--&gt;</li></ul></td><td><ul><li style="text-align:left">SYN --&gt;</li><li style="text-align:left">&lt;-- RST,ACK</li></ul></td></tr></tbody></table>

Open TCP port (SYN):

![](2023-02-16-07-03-56.png)

Closed TCP port (SYN):

![](2023-02-15-12-51-05.png)

The given filter shows the TCP SYN scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`

**UDP Scans**

UDP Scan in a nutshell:

- Doesn't require a handshake process
- No prompt for open ports
- ICMP error message for closed ports
- Usually conducted with `nmap -sU` command.

<table class="table table-bordered"><tbody><tr><td><span style="font-weight:bolder"><span>Open UDP Port</span></span><br></td><td><span style="font-weight:bolder"><span>Closed UDP Port</span></span><br></td></tr><tr><td><ul><li style="text-align:left"><span>UDP packet --&gt;</span></li></ul></td><td><ul><li style="text-align:left"><span>UDP packet --&gt;</span></li><li style="text-align:left">ICMP Type 3, Code 3 message. (Destination unreachable, port unreachable)</li></ul></td></tr></tbody></table>

Closed (port no 69) and open (port no 68) UDP ports:

![](2023-02-16-07-05-53.png)

The above image shows that the closed port returns an ICMP error packet. No further information is provided about the error at first glance, so how can an analyst decide where this error message belongs? The ICMP error message uses the original request as encapsulated data to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request, as shown in the below image.

![](2023-02-15-12-54-39.png)
![](2023-02-15-12-55-01.png)

The given filter shows the UDP scan patterns in a capture file.  

`icmp.type==3 and icmp.code==3`

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

**Questions**

Use the "Desktop/exercise-pcaps/nmap/Exercise.pcapng" file.

- Start Wireshark
- open file

What is the total number of the "TCP Connect" scans?

- `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`
- 1000

Which scan type is used to scan the TCP port 80?

- `tcp.port==80`
- shows 2 scans, first is tcp connect, second is tcp syn
- tcp connect

How many "UDP close port" messages are there?

- `icmp.type==3 and icmp.code==3`
- `icmp.code==3` also works
- 1083

Which UDP port in the 55-70 port range is open?

- **Hint:** Remember, half of the traffic analysis is done by hand when using Wireshark. Filter the traffic as shown in the task, then filter the destination port (UDP) with the "filter a column" option. Finally, scroll the bar in the packet list section and investigate the findings manually.
- `udp.port >=55 && udp.port <=70`
- `udp.port in {55..70}` also works and is easier to read
- scroll and find the open port
- 68

![](2023-02-16-07-22-37.png)

## _**3: ARP Poisoning & Man In The Middle!**_

ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)  

**ARP** protocol, or **A**ddress **R**esolution **P**rotocol (**ARP**), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the **"IP to MAC address table"** and sniff the traffic of the target host.

There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills. 

**ARP analysis in a nutshell:**

- Works on the local network
- Enables the communication between MAC addresses
- Not a secure protocol
- Not a routable protocol
- It doesn't have an authentication function
- Common patterns are request & response, announcement and gratuitous packets.

Before investigating the traffic, let's review some legitimate and suspicious ARP packets. The legitimate requests are similar to the shown picture: a broadcast request that asks if any of the available hosts use an IP address and a reply from the host that uses the particular IP address.

  

<table class="table table-bordered"><tbody><tr><td><b>Notes</b></td><td><b>Wireshark filter</b></td></tr><tr><td>Global search</td><td><ul><li style="text-align:left"><code>arp</code></li></ul></td></tr><tr><td><p style="text-align:left"><span style="font-weight:bolder">"ARP"</span>&nbsp;options for grabbing low-hanging fruit:</p><ul style="text-align:left"><li><span>Opcode 1: ARP requests.</span></li><li><span>Opcode 2: ARP responses.</span></li><li><b>Hunt:</b> Arp scanning</li><li><b>Hunt:</b><span> Possible ARP poisoning detection</span></li><li><b>Hunt:</b><span> Possible ARP flooding from detection:</span></li></ul></td><td><ul><li style="text-align:left"><code>arp.opcode == 1</code></li></ul><ul><li style="text-align:left"><code>arp.opcode == 2</code></li></ul><ul><li style="text-align:left"><code>arp.dst.hw_mac==00:00:00:00:00:00</code></li></ul><ul><li style="text-align:left"><code>arp.duplicate-address-detected or arp.duplicate-address-frame</code></li></ul><ul><li style="text-align:left"><code>((arp) &amp;&amp; (arp.opcode == 1)) &amp;&amp; (arp.src.hw_mac == target-mac-address)</code><br></li></ul></td></tr></tbody></table>

![](2023-02-16-07-32-01.png)

A suspicious situation means having two different ARP responses (conflict) for a particular IP address. In that case, Wireshark's expert info tab warns the analyst. However, it only shows the second occurrence of the duplicate value to highlight the conflict. Therefore, identifying the malicious packet from the legitimate one is the analyst's challenge. A possible IP spoofing case is shown in the picture below.

