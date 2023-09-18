# Velociraptor

Learn Velociraptor, an advanced open-source endpoint monitoring, digital forensic and cyber response platform.

# _**1: Introduction**_

In this room, we will explore Rapid7's newly acquired tool known as [Velociraptor](https://www.rapid7.com/blog/post/2021/04/21/rapid7-and-velociraptor-join-forces/). 

Per the official Velociraptor [documentation](https://docs.velociraptor.app/docs/overview/), "_Velociraptor is a unique, advanced open-source endpoint monitoring, digital forensic and cyber response platform._ _It was developed by Digital Forensic and Incident Response (DFIR) professionals who needed a powerful and efficient way to hunt for specific artifacts and monitor activities across fleets of endpoints. Velociraptor provides you with the ability to more effectively respond to a wide range of digital forensic and cyber incident response investigations and data breaches_".

This tool was created by Mike Cohen, a former Google employee who worked on tools such as [GRR](https://github.com/google/grr) (GRR Rapid Response) and [Rekall](https://github.com/google/rekall) (Rekall Memory Forensic Framework). Mike joined Rapid7's Detection and Response Team and continues to work on improving Velociraptor. At the date of this entry, the latest release for Velociraptor is [0.6.3](https://www.rapid7.com/blog/post/2022/02/03/velociraptor-version-0-6-3-dig-deeper-with-more-speed-and-scalability/).

**Learning Objectives**

- Learn what is Velociraptor
- Learn how to interact with agents and create collections
- Learn how to interact with the virtual file system
- Learn what is VQL and how to create basic queries
- Use Velociraptor to perform a basic hunt

**Prerequisites**

- [Windows Forensics 1](https://tryhackme.com/room/windowsforensics1)
- [Windows Forensics 2](https://tryhackme.com/room/windowsforensics2)
- [KAPE](https://tryhackme.com/room/kape)


# _**2: Deployment**_

**Deploying Velociraptor**

Velociraptor is unique because the Velociraptor executable can act as a **server** or a **client** and it can run on **Windows**, **Linux**, and **MacOS**.  Velociraptor is also compatible with cloud file systems, such as **Amazon EFS** and **Google Filestore**. 

Velociraptor can be deployed across thousands, even tens of thousands, client endpoints and runs surprisingly well for an open-source product. 

In this task, we will **NOT** go into detail about how to deploy Velociraptor as a server and agent architecture in an environment. Rather, in the attached virtual machine, you will run the commands to start the first Velociraptor executable as a server and execute a second Velociraptor executable to run as an agent. This is possible thanks to WSL ([Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/about)). This will simulate Velociraptor running as a server in Linux (Ubuntu) and as a client running Windows. WSL (Windows Subsystem for Linux) allows us to run a Linux environment in a Windows machine without the need for a virtual machine. 

Let's start Velociraptor as a server. If you haven't done so, deploy the attached virtual machine. 

After fully loading, the virtual machine will appear in split view in your web browser. If you don't see the VM, click **Show Split View**. 

![split view](https://assets.tryhackme.com/additional/velociraptor/split-view-2.png)

For a better experience, expand the Split View to full-screen mode.

 ![full screen](https://assets.tryhackme.com/additional/velociraptor/expand-split-view.png)

There is a text file on the desktop called commands.txt. Open the Ubuntu terminal and run the command for `Start the Velociraptor Server (Ubuntu Terminal)`.

![taskbar](https://assets.tryhackme.com/additional/velociraptor/ubuntu-taskbar.png)  

Below is an example of the terminal input and output. 

Start the Velociraptor Server (Ubuntu Terminal)

```
tryhackme@THM-VELOCIRAPTOR:~$ ./velociraptor-v0.5.8-linux-amd64 --config velociraptor.config.yaml frontend -v
[INFO] 2022-05-17T15:39:57-07:00  _    __     __           _                  __
[INFO] 2022-05-17T15:39:57-07:00 | |  / /__  / /___  _____(_)________ _____  / /_____  _____
[INFO] 2022-05-17T15:39:57-07:00 | | / / _ \/ / __ \/ ___/ / ___/ __ `/ __ \/ __/ __ \/ ___/
[INFO] 2022-05-17T15:39:57-07:00 | |/ /  __/ / /_/ / /__/ / /  / /_/ / /_/ / /_/ /_/ / /
[INFO] 2022-05-17T15:39:57-07:00 |___/\___/_/\____/\___/_/_/   \__,_/ .___/\__/\____/_/
[INFO] 2022-05-17T15:39:57-07:00                                   /_/
[INFO] 2022-05-17T15:39:57-07:00 Digging deeper!                  https://www.velocidex.com
[INFO] 2022-05-17T15:39:57-07:00 This is Velociraptor 0.5.8 built on 2021-04-11T22:09:54Z (e468f54c)
[INFO] 2022-05-17T15:39:57-07:00 Loading config from file velociraptor.config.yaml
[INFO] 2022-05-17T15:39:57-07:00 Starting Frontend. {"build_time":"2021-04-11T22:09:54Z","commit":"e468f54c","version":"0.5.8"}
[INFO] 2022-05-17T15:39:57-07:00 Error increasing limit invalid argument. This might work better as root.
[INFO] 2022-05-17T15:39:57-07:00 Starting Journal service.
[INFO] 2022-05-17T15:39:57-07:00 Starting the notification service.
[INFO] 2022-05-17T15:39:57-07:00 Starting Inventory Service
[INFO] 2022-05-17T15:39:57-07:00 Loaded 250 built in artifacts in 155.397ms
[INFO] 2022-05-17T15:39:57-07:00 Starting Label service.
[INFO] 2022-05-17T15:39:57-07:00 Selected frontend configuration localhost:8000
[INFO] 2022-05-17T15:39:57-07:00 Starting Client Monitoring Service
[INFO] 2022-05-17T15:39:57-07:00 Reloading client monitoring tables from datastore
[INFO] 2022-05-17T15:39:57-07:00 Starting Hunt Dispatcher Service.
[INFO] 2022-05-17T15:39:57-07:00 Starting the hunt manager service.
[INFO] 2022-05-17T15:39:57-07:00 server_monitoring: Starting Server Monitoring Service
[INFO] 2022-05-17T15:39:57-07:00 Closing Server Monitoring Event table
[INFO] 2022-05-17T15:39:57-07:00 server_monitoring: Updating monitoring table
[INFO] 2022-05-17T15:39:57-07:00 Starting Enrollment service.
[INFO] 2022-05-17T15:39:57-07:00 server_monitoring: Collecting Server.Monitor.Health/Prometheus
[INFO] 2022-05-17T15:39:57-07:00 Starting VFS writing service.
[INFO] 2022-05-17T15:39:57-07:00 Starting Server Artifact Runner Service
[INFO] 2022-05-17T15:39:57-07:00 Starting gRPC API server on 127.0.0.1:8001
[INFO] 2022-05-17T15:39:57-07:00 Launched Prometheus monitoring server on 127.0.0.1:8003
[INFO] 2022-05-17T15:39:57-07:00 GUI is ready to handle TLS requests on https://127.0.0.1:8889/
[INFO] 2022-05-17T15:39:57-07:00 server_monitoring: Finished collecting Server.Monitor.Health/Prometheus
[INFO] 2022-05-17T15:39:57-07:00 Frontend is ready to handle client TLS requests at https://localhost:8000/
[INFO] 2022-05-17T15:39:57-07:00 Query Stats: {"RowsScanned":1,"PluginsCalled":1,"FunctionsCalled":0,"ProtocolSearch":0,"ScopeCopy":5}
[INFO] 2022-05-17T15:39:58-07:00 Compiled all artifacts.
```
        

It's worth noting that the version of Velociraptor running in the attached virtual machine is **0.5.8**. Now launch Google Chrome and click the Velociraptor shortcut. 

![Start Velociraptor](https://assets.tryhackme.com/additional/velociraptor/google-shortcut.png)  

Chrome is likely to show you "_Your Connection is not private errors"_, this is expected and you can proceed to 127.0.01 via the advanced option.  

The credentials for the Velociraptor server are:

- Username: `thmadmin`
- Password: `tryhackme`

If all goes well, you should see the Velociraptor [Welcome screen](https://docs.velociraptor.app/docs/gui/#the-welcome-screen). 

![Welcome Screen](https://assets.tryhackme.com/additional/velociraptor/welcome-screen.png)  

If you wish to interact and deploy Velociraptor locally in your lab, then **[Instant Velociraptor](https://docs.velociraptor.app/docs/deployment/#instant-velociraptor)** is for you. Instant Velociraptor is a fully functional Velociraptor system that is deployed only to your local machine.

Refer to the official [documentation](https://docs.velociraptor.app/docs/deployment/) for more information on deploying Velociraptor as a server/client infrastructure or as Instant Velociraptor. 

## _**Answer the questions below**_

 Using the [documentation](https://docs.velociraptor.app/docs/deployment/#instant-velociraptor), how would you launch an Instant Velociraptor on Windows?

- Velociraptor.exe gui



# 3: Interacting with client machines

**Inspecting Clients**

If you didn't notice, some links are grayed out when you first log into Velociraptor. See below.

![grayed menu icons](https://assets.tryhackme.com/additional/velociraptor/dashboard-grayed-out-links.png)  

These links are specific to client endpoints and will become active once the analyst interacts with these endpoints within the Velociraptor UI. 

Let's add a client to Velociraptor. Remember, since the attached VM is running Windows Subsystem for Linux (WSL), the Velociraptor server is running in Ubuntu, but the client will be Windows. 

Run the commands for 'Add Windows as a client (CMD)' from the commands.txt on the desktop.

Add Windows as a client (CMD)

```
C:\Program Files\Velociraptor> velociraptor-v0.5.8-windows-amd64.exe --config velociraptor.config.yaml client -v
[INFO] 2022-03-31T05:47:36-07:00  _    __     __           _                  __
[INFO] 2022-03-31T05:47:36-07:00 | |  / /__  / /___  _____(_)________ _____  / /_____  _____
[INFO] 2022-03-31T05:47:36-07:00 | | / / _ \/ / __ \/ ___/ / ___/ __ `/ __ \/ __/ __ \/ ___/
[INFO] 2022-03-31T05:47:36-07:00 | |/ /  __/ / /_/ / /__/ / /  / /_/ / /_/ / /_/ /_/ / /
[INFO] 2022-03-31T05:47:36-07:00 |___/\___/_/\____/\___/_/_/   \__,_/ .___/\__/\____/_/
[INFO] 2022-03-31T05:47:36-07:00                                   /_/
[INFO] 2022-03-31T05:47:36-07:00 Digging deeper!                  https://www.velocidex.com
[INFO] 2022-03-31T05:47:36-07:00 This is Velociraptor 0.5.8 built on 2021-04-11T22:11:10Z (e468f54c)
[INFO] 2022-03-31T05:47:36-07:00 Loading config from file velociraptor.config.yaml
Generating new private key....
[INFO] 2022-03-31T05:47:36-07:00 Setting temp directory to C:\Program Files\Velociraptor\Tools
[...]
```
        

To see the client and interact with it, click on the `magnifying glass` with an empty search query (no text in the search bar) or click `Show All`.

![search for clients](https://assets.tryhackme.com/additional/velociraptor/search-clients.png)  

The output will display a list of client machines running the Velociraptor agent in a table form.

![client list](https://assets.tryhackme.com/additional/velociraptor/client-list.png)  

Below is a brief explanation of each column.

<table class="table table-bordered"><tbody><tr><td><b>Online State</b></td><td>A green dot indicates the endpoint is online and communicating with the Velociraptor server. A yellow dot means the server hasn't received any communication from the endpoint within a 24-hour time frame. A red dot means it's been more than 24 hours since the server last heard from the endpoint.&nbsp;</td></tr><tr><td><b>Client ID</b></td><td>This is a unique ID assigned to the client by the Velociraptor server, and the server will use this client ID to identify the endpoint. A client ID always starts with the letter <b>C</b>.</td></tr><tr><td><b>Hostname</b></td><td>This is the hostname the client identifies itself to the Velociraptor server. Remember that hostnames can change, hence why Velociraptor uses the Client ID instead of identifying a client machine.&nbsp;</td></tr><tr><td><b>Operating System Version</b></td><td><span>The Velociraptor client can run on Windows, <a class="lD9kK4Tg glossary-term" onclick="initPopOver('Linux', 'lD9kK4Tg')" href="">Linux</a>, or MacOS. The details regarding the client operating system are displayed in this column.&nbsp;</span></td></tr><tr><td><b>Labels</b></td><td>Client machines may have multiple labels attached to them. This is useful to identify multiple clients as a group.</td></tr></tbody></table>

 Click on the agent to bring you to a semi-detailed view. By default, the view shown is the **overview** for the client.  

**Overview**

In this view, the analyst (you) will see additional information about the client. The additional details are listed below:

- **Client ID**
- **Agent Version**
- **Agent Name**
- **Last Seen At**
- **Last Seen IP**
- **Operating System**
- **Hostname**
- **Release**
- **Architecture**
- **Client Metadata**

**VQL Drilldown**  
In this view, there is additional information about the client, such as Memory and CPU usage over 24 hours timespan, the Active Directory domain if the client is a domain-joined machine and the active local accounts for the client.  

The data is represented in two colors in the Memory and CPU footprint over the past 24 hours.

- **Orange** - Memory usage
- **Blue** - CPU usage

**Shell**

With the shell, commands can be executed remotely on the client machine. Commands can be run in  **PowerShell**, **CMD**, **Bash**, or **VQL**. Depending on the target operating system will determine which the analyst will pick. For example, CMD will not be a viable option if the client machine is running Linux. 

It's straightforward, choose one of the options to run the command in and click `Launch`. 

In the example below, the command `whoami` was executed with PowerShell. The command results are not immediately visible, and the **eyeball** icon needs to be toggled to see the command results. 

![](https://assets.tryhackme.com/additional/velociraptor/powershell-whoami.png)  

**Collected**

Here the analyst will see the results from the commands executed previously from Shell. Other actions, such as interacting with the **VFS** (**Virtual File System**), will appear here in Collected. VFS will be discussed later in upcoming tasks.

Across the top pane are brief details of the' collected' artifact. See below.

![collected](https://assets.tryhackme.com/additional/velociraptor/collected1.png)  

  

Clicking on any FlowId will populate the bottom pan with additional details regarding the information collected for that artifact or collection.  

In the below screenshot, the output is from **Artifact Collection**. 

![collected](https://assets.tryhackme.com/additional/velociraptor/collected2b.png)  

This section is very busy, and I'll leave you to acquaint yourself with the information displayed here for each collected artifact.   

The questions in this task will help nudge you to navigate throughout the output returned for each shell execution (e.i. whoami).

In the next task, we'll explore how to create a new collection and review the results in Collected. 

**Interrogate**

Per the [documentation](https://docs.velociraptor.app/docs/gui/clients/), "Interrogate operation. Interrogation normally occurs when the client first enrolls, but you can interrogate any client by clicking the Interrogate button".

To confirm this, click `Interrogate`. Now navigate back to Collected. You will notice that the **Artifact Collection** is **Generic. Client.Info**, which is an additional collection on the list. The first artifact collection in the list is indeed **Generic.Client.Info**. This is the same information displayed under **VQL Drilldown**.  

Refer to the official Velociraptor documentation titled [Inspecting Clients](https://docs.velociraptor.app/docs/gui/clients/) for additional information. 

## _**Answer the questions below**_

What is the hostname for the client?

- thm-velociraptor.eu-west-1.compute.internal

What is listed as the agent version?

- 2021-04-11T22:11:10Z

In the Collected tab, what was the VQL command to query the client user accounts?

- `LET Generic_Client_Info_Users_0_0=SELECT Name, Description, Mtime AS LastLogin FROM Artifact.Windows.Sys.Users()`

In the Collected tab, check the results for the PowerShell whoami command you executed previously. What is the column header that shows the output of the command?

- Stdout

In the Shell, run the following PowerShell command Get-Date. What was the PowerShell command executed with VQL to retrieve the result?

- `powershell -ExecutionPolicy Unrestricted -encodedCommand RwBlAHQALQBEAGEAdABlAA==`



# 4: Creating a new collection

**Creating a new collection**

In this task let's create a new collection.

- Click on Client ID 
- Click on Collected Artifacts
- Click on New Collection

![](./Velociraptor/2023-09-18-07-36-31.png)
![new collection](https://assets.tryhackme.com/additional/velociraptor/new-collection.png)  

We will take advantage of the WSL set-up in the attached VM and choose an artifact specific to Ubuntu. 

There will be 5 stages in this process.

- **Select Artifacts**
- **Configure Parameters**
- **Specify Resources**
- **Review**
- **Launch**

**Select Artifacts**

In the search bar, type `Windows.KapeFiles.Targets`. If you're not familiar with **KAPE**, please visit the KAPE [room](https://tryhackme.com/room/kape). 

In short, **KapeFiles** are community-created targets and modules for use with KAPE. But as you can see, other tools use these Kapefiles as well. 

When you select the artifact, a brief description of the collector will be displayed on the right, along with a rundown of the parameters. 

![select artifacts](https://assets.tryhackme.com/additional/velociraptor/select-artifacts2.png)  

**Configure Parameters**  

![configure parameters](https://assets.tryhackme.com/additional/velociraptor/configure-parameters.png)

Scroll down and check **Ubuntu**.

![check ubuntu](https://assets.tryhackme.com/additional/velociraptor/check-ubuntu.png)  

Next, click on **Specify Resources**.

**Specify Resources**

You can leave this untouched. See the below screenshot.

![specify resources](https://assets.tryhackme.com/additional/velociraptor/specify-resources.png)  

Next, click on **Review**.

**Review**

 The output will display in JSON format and it's pretty straightforward. Only one setting was enabled to collect, which was Ubuntu.   

![review request](https://assets.tryhackme.com/additional/velociraptor/review-request.png)

**Launch**

Everything should be in order. Now it's time to launch the collection to gather the artifacts. 

When you click **Launch**, you will be redirected to the Collected view. Notice that there should be a new entry with the newly created collection. 

In particular, notice the State. It should show an hourglass which indicates the artifacts are actively being gathered for that collection. 

![collection is running](https://assets.tryhackme.com/additional/velociraptor/collection-running.png)  

Once the artifacts have been gathered, the state will change from an hourglass to a checkmark like the others. 

![collection is done](https://assets.tryhackme.com/additional/velociraptor/collection-done-2.png)  

As the list of collections grows, you can search for specific collections using the textfield at the top of the column. See the above screenshot. 

Sweet! Now that we got that covered, let's look at VFS. 

Refer to the Velociraptor documentation to learn more about [Artifacts](https://docs.velociraptor.app/docs/gui/artifacts/). 

## _**Answer the questions below**_

Earlier you created a new artifact collection for Windows.KapeFiles.Targets. You configured the parameters to include Ubuntu artifacts. Review the parameter description for this setting. What is this parameter specifically looking for?

- Ubuntu on Windows Subsystem for Linux

![](./Velociraptor/2023-09-18-07-50-42.png)

Review the output. How many files were uploaded?

- 20 
- Mine shows 19

![](./Velociraptor/2023-09-18-07-51-49.png)



# 5: VFS (Virtual File System)

**The Virtual File System**

Per the [documentation](https://docs.velociraptor.app/docs/gui/vfs/), "_The VFS is simply a server side cache of the files on the endpoint. It is merely a familiar GUI to allow inspection of the client’s filesystem_".

This can prove useful in an incident response scenario where you, the analyst, need to inspect artifacts in a client. 

Refer to the official documentation for a complete overview of the VFS. In this task, we're going to focus on getting hands-on with VFS.

Below is what you should see when you first access the VFS for a client. 

![VFS](https://assets.tryhackme.com/additional/velociraptor/default-vfs.png)  

In the left pane, along with the middle pane, there are 4 folders (or accessors, filesystem access drivers):

- **file - uses operating system APIs to access files**
- **ntfs - uses raw NTFS parsing to access low level files**
- **registry - uses operating system APIs to access the Windows registry**
- **artifacts - previously run collections.** 

Three buttons are highlighted in the above image. Below is a brief explanation for each.

![VFS buttons](https://assets.tryhackme.com/additional/velociraptor/vfs-buttons-2.png)

1. Refresh the current directory (sync its listing from the client)
2. Recursively refresh this directory (sync its listing from the client)
3. Recursively download this directory from the client

Let's continue interacting with VFS.

When any folder is clicked  in the left pane, additional details are displayed in the middle pane. For example, if the file folder is clicked, a subfolder will appear, which is **C:**. Now the details in the middle pane change to reflect C:.

## _**Answer the questions below**_

Which accessor can access hidden NTFS files and Alternate Data Streams? (**format: xyz accessor)**

- 

Which accessor provides file-like access to the registry? (format: xyz accessor)

- 

What is the name of the file in $Recycle.Bin?

- 

There is hidden text in a file located in the Admin's Documents folder. What is the flag?

- 



# 6: 