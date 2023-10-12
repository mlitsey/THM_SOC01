# **Autopsy**
  
Learn how to use Autopsy to investigate artefacts from a disk image. Use your knowledge to investigate an employee who is being accused of leaking private company data.

[Link](https://tryhackme.com/room/btautopsye0)


# _**1: Introduction**_

Autopsy is an open-source and powerful digital forensics platform. Several features within Autopsy have been developed by the Department of Homeland Security Science and Technology funding. You can read more about this [here](https://www.dhs.gov/science-and-technology/news/2017/12/12/snapshot-st-enhancing-autopsy-digital-forensics-tool). 

[**The official description**](https://www.autopsy.com/): "_Autopsy is the premier open source forensics platform which is fast, easy-to-use, and capable of analysing all types of mobile devices and digital media. Its plug-in architecture enables extensibility from community-developed or custom-built modules. Autopsy evolves to meet the needs of hundreds of thousands of professionals in law enforcement, national security, litigation support, and corporate investigation._"

This room's objective is to provide an overview of using the Autopsy tool to analyse disk images. The assumption is that you are familiar with the Windows operating system and Windows artefacts in relation to forensics.


# _**2: Workflow Overview and Case Analysis**_

## **Workflow Overview**  

Before diving into Autopsy and analysing data, there are a few steps to perform; such as identifying the data source and what Autopsy actions to perform with the data source. 

Basic workflow:

1. Create/open the case for the data source you will investigate
2. Select the data source you wish to analyse
3. Configure the ingest modules to extract specific artefacts from the data source
4. Review the artefacts extracted by the ingest modules
5. Create the report

## **Case Analysis | Create a New Case**  

To prepare a new case investigation, you need to create a case file from the data source. When you start Autopsy, there will be three options. You can create a new case file using the **"New Case"** option. Once you click on the "New Case" option, the **Case Information** menu opens**,** where information about the case is populated.

- **Case Name**: The name you wish to give to the case
- **Base Directory**: The root directory that will store all the files specific to the case (the full path will be displayed)
- **Case Type**: Specify whether this case will be local (**Single-user**) or hosted on a server where multiple analysts can review (**Multi-user**)

**Note**: In this room, the focus is on **Single-User**. Also, the room doesn't simulate a new case creation, and the given VM has a sample case file to practice covered Autopsy features.

The following screen is titled "**Optional Information"** and can be left blank for our purposes. In an actual forensic environment, you should fill out this information. Once you click on "Finish", Autopsy will create a new case file from the given data source.  

![Autopsy - Create a new case](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e488c3548327c1bd78aff63060e2d2a9.png)

Case Analysis | Open an Existing Case  

The Autopsy can also open prebuilt case files. Note that supported data sources are discussed in the next task. This part aims to show how to create/open case files with Autopsy.

**Note:** Autopsy case files have a ".aut" file extension.  

**In this room, you will import a case.** To open a case, select the "Open Case" option. Navigate to the case folder (located on the desktop) and select the .aut file you wish to open. Next, Autopsy will process the case files and open the case. You can identify the name of the case at the top left corner of the Autopsy window. In the image below, the name of this case is **"Sample Case"**.   

![Autopsy - Open an existing case](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e54b49da6843e66582b797a8a3553723.png)

![Autopsy - Case view](https://assets.tryhackme.com/additional/autopsy/autopsy-casename2.png)

**Note**: A warning box will appear if Autopsy cannot locate the disk image. At this point, you can point to the location of the disk image it's attempting to find, or you can click **NO**; you can still analyse the data from the Autopsy case. 

 ![Autopsy - Missing image](https://assets.tryhackme.com/additional/autopsy/autopsy-missing-image3.png)

Once the case you wish to analyse is open, you are ready to start exploring the data.  

**Questions**

What is the file extension of the Autopsy files?
- .aut


# _**3: Data Sources**_

**Data Sources**

Autopsy can analyse multiple disk image formats. Before diving into the data analysis step, let's briefly cover the different data sources Autopsy can analyse. You can add data sources by using the **"Add Data Source"** button. Available options are shown in the picture below.  

![Autopsy - Data sources](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c75224413dfb9884adbdc8c5a778383d.png)

**We will focus primarily on the Disk Image or VM File option in this room.**   

Supported Disk Image Formats:

- **Raw Single** (For example: \*.img, \*.dd, \*.raw, \*.bin)
- **Raw Split** (For example: \*.001, \*.002, \*.aa, \*.ab, etc)
- **EnCase** (For example: \*.e01, \*.e02, etc)
- **Virtual Machines** (For example: \*.vmdk, \*.vhd)

If there are multiple image files (e.i. E01, E02, E03, etc.) Autopsy only needs you to point to the first image file, and Autopsy will handle the rest.  

**Note**: Refer to the Autopsy [documentation](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ds_page.html) to understand the other data sources that can be added to a case. 

**Questions**

What is the disk image name of the "e01" format?

- EnCase


# _**4: Ingest Modules**_

Essentially **Ingest Modules** are Autopsy plug-ins. Each Ingest Module is designed to analyse and retrieve specific data from the drive. You can configure Autopsy to run specific modules during the source-adding stage or later by choosing the target data source available on the dashboard. By default, the Ingest Modules are configured to run on All Files, Directories, and Unallocated Space. You can change this setting during the module selecting step. You can track the process with the bar appearing in the lower right corner.

The below screenshots simulate mentioned two different approaches to using ingest modules. Note that using ingest modules requires time to implement. Therefore we will not cover ingest modules in this room.

Note: Autopsy adds metadata about files to the local database, not the actual file contents. 

**Configuring ingest modules while adding data sources:**  
  

![Autopsy - Configuring ingest module while adding data source](https://assets.tryhackme.com/additional/autopsy/autopsy-configure-modules.png)

**Using ingest modules after adding data sources:**

1. Open the "Run Ingest Modules" menu by right-clicking on the data source.
2. Choose the modules to implement and click on the finish button.
3. Track the progress of implementation.

![Autopsy - Use ingest module after adding data sources](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/04138be7675286ea5f9066a893c0b199.png)  

The results of any Ingest Module you select to run against a data source will populate the Results node in the Tree view, which is the left pane of the Autopsy user interface. Below is an example of using the **"Interesting Files Identifier"** ingest module. Note that the results depend on the dataset. If you choose a module to retrieve specific data that is unavailable in the drive, there will be no results.

![Autopsy - Ingest module sample result](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/9ee9f606ea3444fd04c45b15c2c7f819.png)  

Drawing the attention back to the Configure Ingest Modules window, notice that some Ingest Modules have per-run settings and some do not. For example, the Keyword Search Ingest Module does not have per-run settings. In contrast, the Interesting Files Finder Ingest Module does. The yellow triangle represents the "per-run settings option".

As Ingest Modules run, alerts may appear in the **Ingest Inbox**. Below is an example of the Ingest Inbox after a few Ingest Modules have completed running. 

![Autopsy - Ingest inbox](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/212c83e75693ce2d8f485633a11dd697.png)

To learn more about Ingest Modules, read Autopsy documentation [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ingest_page.html). 



# _**5: The User Interface I**_

Let's look at the Autopsy user interface, which is comprised of 5 primary areas: 

## **Tree Viewer**

![Autopsy - Tree view](https://assets.tryhackme.com/additional/autopsy/autopsy-tree-view.png)

The **Tree Viewer** has **five top-level nodes**:

- **Data Sources** \- all the data will be organised as you would typically see it in a normal Windows File Explorer. 
- **Views** - files will be organised based on file types, MIME types, file size, etc. 
- **Results** - as mentioned earlier, this is where the results from Ingest Modules will appear. 
- **Tags** - will display files and/or results that have been tagged (read more about tagging [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tagging_page.html)).
- **Reports** - will display reports either generated by modules or the analyst (read more about reporting [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/reporting_page.html)).

Refer to the Autopsy documentation on the **Tree Viewer** for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tree_viewer_page.html). 

## **Result Viewer**

**Note**: Don't confuse the Results node (from the Tree Viewer) with the Result Viewer. 

When a volume, file, folder, etc., is selected from the Tree Viewer, additional information about the selected item is displayed in the Result Viewer. For example, the Sample case's data source is selected, and now additional information is visible in the Results Viewer. 

![Autopsy - Table view 1](https://assets.tryhackme.com/additional/autopsy/autopsy-table-view.png)  

If a volume is selected, the Result Viewer's information will change to reflect the information in the local database for the selected volume. 

![Autopsy - Table view 2](https://assets.tryhackme.com/additional/autopsy/autopsy-table-view2.png)  

Notice that the Result Viewer pane has three tabs: **Table**, **Thumbnail**, and **Summary**. The above screenshots reflect the information displayed in the Table tab. The Thumbnail tab works best with image or video files. If the view of the above data is changed from Table to Thumbnail, not much information will be displayed. See below.

![Autopsy - Thumbnail view](https://assets.tryhackme.com/additional/autopsy/autopsy-thumbnail-view.png)  

Volume nodes can be expanded, and an analyst can navigate the volume's contents like a typical Windows system. 

![Autopsy - Volume](https://assets.tryhackme.com/additional/autopsy/autopsy-volume.png)  

In the **Views** tree node, files are categorised by File Types - **By Extension, By** **MIME Type**, **Deleted Files**, and **By** **File Size**.

![Autopsy - Views](https://assets.tryhackme.com/additional/autopsy/autopsy-views.png) 

**Tip**: When it comes to **File Types**, pay attention to this section. An adversary can rename a file with a misleading file extension. So the file will be 'miscategorised' **By** **Extension** but will be categorised appropriately by **MIME Type**. Expand **By Extension** and more children nodes appear, categorising files even further (see below).

![Autopsy - By extension](https://assets.tryhackme.com/additional/autopsy/autopsy-byextension.png)  

Refer to the Autopsy documentation on the **Result Viewer** for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/result_viewer_page.html).   

## **Contents Viewer**

From the Table tab in the Result Viewer, if you click any folder/file, additional information is displayed in the Contents Viewer pane.   

![Autopsy - Contents view](https://assets.tryhackme.com/additional/autopsy/autopsy-contents-view.png)

In the given image, three columns might not be quickly understood what they represent. 

- **S** = **Score**

The **Score** will show a red exclamation point for a folder/file marked/tagged as notable and a yellow triangle pointing downward for a folder/file marked/tagged as suspicious. These items can be marked/tagged by an Ingest Module or the analyst.

- **C** \= **Comment**

If a yellow page is visible in the Comment column, it will indicate that there is a comment for the folder/file. 

- **O** = **Occurrence** 

In a nutshell, this column will indicate how many times this file/folder has been seen in past cases (this will require the [Central Repository](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/central_repo_page.html))

Refer to the Autopsy documentation on the Contents Viewer for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/content_viewer_page.html).   

## **Keyword Search**

At the top right, you will find **Keyword Lists** and **Keyword Search**. With **Keyword Search,** an analyst can perform an AD-HOC keyword search. 

![Autopsy - Keyword Search 1](https://assets.tryhackme.com/additional/autopsy/autopsy-keyword-search.png)  

In the image above, the analyst searches for the word 'secret.' Below are the search results.

![Autopsy - Keyword search 2](https://assets.tryhackme.com/additional/autopsy/autopsy-keyword-search2.png)  

Refer to the Autopsy [documentation](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ad_hoc_keyword_search_page.html) for more information on performing keyword searches with either option. 

## **Status Area**

Lastly, the **Status Area** is at the bottom right. When Ingest Modules run, a progress bar (along with the percentage completed) will be displayed in this area. More detailed information regarding the Ingest Modules is provided if you click on the bar.   

![Autopsy - Status bar](https://assets.tryhackme.com/additional/autopsy/autopsy-statusbar2.png)  

If the `X` (directly next to the progress bar) is clicked, a prompt will appear confirming if you wish to end/cancel the Ingest Modules. 

Refer to the Autopsy documentation on the UI overview [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/uilayout_page.html). 

**Questions**

Expand the "Data Sources" option; what is the number of available sources?

- 4

![4 volumes](./Autopsy/2023-05-19-07-44-28.png)

What is the number of the detected "Removed" files?

- 10

![Recycle Bin](./Autopsy/2023-05-19-07-46-39.png)

What is the filename found under the "Interesting Files" section?

- googledrivesync.exe

![Interesting Files](2023-05-19-07-48-29.png)



# _**6: The User Interface II**_

Let's look at where we can find summarised info with ease. Summarised info can help analysts decide where to focus by evaluating available artefacts. It is suggested to view the summary of the data sources before starting an investigation. Therefore you can have a general idea about the system and artefacts.

## **Data Sources Summary**

The **Data Sources Summary** provides summarised info in nine different categories. Note that this is an overview of the total findings. If you want to dive deep into the findings and look for a specific artefact, you need to analyse each module separately using the **"Result Viewer"** shown in the previous task. 

![Autopsy - Data sources summary](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a8ab6999fabaf538c2e9eb3742b0ff29.png)  

## **Generate Report**

You can create a report of your findings in multiple formats, enabling you to create data sheets for your investigation case. The report provides all information listed under the "Result Viewer" pane. Reports can help you to re-investigate findings after finishing the live investigation. **However, reports don't have additional search options, so you must manually find artefacts for the event of interest.**

**Tip:** The Autopsy tool can be heavy for systems with low resources. Therefore completing an investigation with Autopsy on low resources can be slow and painful. Especially browsing long results might end up with a system freeze. You can avoid that situation by using reports. You can use the tool for parsing the data and generating the report, then continue to analyse through the generated report without a need for Autopsy. Note that it is always easier to conduct and manage an investigation with the GUI.

You can use the **"Generate Report"** option to create reports. The steps are shown below.  
  

![Autopsy - Generate report](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/581fe3b1caa19ed94ad2564e3ecd8003.png)  

Once you choose your report format and scope, Autopsy will generate the report. You can click on the "HTML Report" section (shown above) to view the report on your browser. Reports contain all of the "Result Viewer" pane results on the left side.

![Autopsy - HTML report sample](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/68fc3dcf815f47183dd62c35438dc98c.png)  

**Questions**

What is the full name of the operating system version?

- Windows 7 Ultimate Service Pack 1

![](./Autopsy/2023-05-19-08-02-59.png)

What percentage of the drive are documents? Include the % in your answer.

- 40.8%

Generate an HTML report as shown in the task and view the "Case Summary" section.
What is the job number of the "Interesting Files Identifier" module?

- 10
- Generate Report -> HTML Report -> Next -> select data source -> Next -> Select data -> Finish



# _**7: Data Analysis**_

**Mini Scenario**: An employee was suspected of leaking company data. A disk image was retrieved from the machine. You were assigned to perform the initial analysis. Further action will be determined based on the initial findings. 

**Reminder:** Since the actual disk image is not in the attached VM, certain Autopsy sections will not display any actual data, only the metadata for that row within the local database. You can click **No** when you're notified about the '**Missing Image**.' Additionally, you do **not** need to run any ingest modules in this exercise. 

![Autopsy - Missing image](https://assets.tryhackme.com/additional/autopsy/autopsy-missing-image2.png)

**Questions**

What is the name of an Installed Program with the version number of 6.2.0.2962?

- Eraser

![](./Autopsy/2023-05-22-06-40-06.png)

A user has a Password Hint. What is the value?

- IAMAN

![](./Autopsy/2023-05-22-06-53-39.png)

Numerous SECRET files were accessed from a network drive. What was the IP address?

- 10.11.11.128

![](./Autopsy/2023-05-22-06-55-42.png)

What web search term has the most entries?

- information leakage cases

![](./Autopsy/2023-05-22-06-57-25.png)

What was the web search conducted on 3/25/2015 21:46:44?

- anti-forensic tools

![](./Autopsy/2023-05-22-06-59-01.png)

What MD5 hash value of the binary is listed as an Interesting File?

- To copy the hash value, you can use the "File Metadata" section (shown in Task-5 - Contents Viewer). Choose an artefact from the list and copy the hash value from the "File Metadata" section with CTRL+C.
- fe18b02e890f7a789c576be8abccdc99

![](./Autopsy/2023-05-22-07-04-05.png)

What self-assuring message did the 'Informant' write for himself on a Sticky Note? (no spaces)

- Navigate to Data Sources/sample-case.dd/vol3/Users/informant/AppData/Roaming/Microsoft/Sticky Notes/
- Select StickyNotes.snt
- Read the text 
- Tomorrow...Everything will be OK...

![](./Autopsy/2023-05-22-07-29-40.png)


# _**8: Visualisation Tools**_

You may have noticed that other parts of the user interface weren't discussed as of yet. 

![Autopsy - Top bar](https://assets.tryhackme.com/additional/autopsy/autopsy-top-bar.png)  

Please refer to the Autopsy documentation for the following visualisation tool:

- **Images/Videos:** [http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/image\_gallery\_page.html](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/image_gallery_page.html)
- **Communications:** [http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/communications\_page.html](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/communications_page.html)
- **Timeline:** [http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/timeline\_page.html](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/timeline_page.html)

**Note**: Within the attached VM, you will **NOT** be able to practice with some of the visualisation tools, except for **Timeline**. Below is a screenshot of the **Timeline**.

![Autopsy - Timeline](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline.png)

**The Timeline tool is composed of three areas:**

1. **Filters:** Narrow the events displayed based on the filter criteria
2. **Events:** The events are displayed here based on the **View Mode**
3. **Files/Contents:** Additional information on the event(s) is displayed in this area

**There are three view modes:**

1. **Counts:** The number of events is displayed in a bar chart view
2. **Details:** Information on events is displayed, but they are clustered and collapsed, so the UI is not overloaded
3. **List:** The events are displayed in a table view

In the above screenshot, the View Mode is **Counts**. Below is a screenshot of the **Details** View Mode. 

![Autopsy - Timeline details](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-details.png)  

The numbers (seen above) indicate the number of clustered/collapsed events for a specific time frame. For example, for /Windows, there are 130,257 events between 2009-06-10 and 2010-03-18. See the below image. 

![Autopsy - Timeline clustured 1](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-clustered.png)  

To expand a cluster, click on the `green icon with the plus sign`. See the below example.

![Autopsy - Cluster expand](https://assets.tryhackme.com/additional/autopsy/autopsy-cluster-expand.png)  

To collapse the events, click on the `red icon with a minus sign`. Click `the map marker icon with a plus sign` if you wish to pin a group of events. This will move (pin) the events to an isolated section of the Events view. 

![Autopsy - Timeline clustered 2](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-clustered2.png)  

To unpin the events, click on the `map marker with the minus sign`. The last group of icons to cover are the `eye` icons. If you wish to hide a group of events from the Events view, click on the `eye with a minus sign`. In the below screenshot, the clustered events for /Boot were hidden and placed in `Hidden Descriptions` (in the Filters area).

 ![Autopsy - Timeline hidden](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-hidden.png)

If you wish to reverse that action and unhide the events, right-click and select `Unhide and remove from list`. See the below example.

![Autopsy - Timeline unhide](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-unhide.png)  

Last but not least, a screenshot of the **List** View Mode is below.  

![Autopsy - Timeline list](https://assets.tryhackme.com/additional/autopsy/autopsy-timeline-list.png)  

This should be enough information to get you started interacting with the Timeline with some level of confidence. 

**Questions**

Using the Timeline, how many results were there on 2015-01-12?

- 46
- After narrowing down the dates, select the red bar to show the count of results

![](./Autopsy/2023-05-22-07-39-33.png)

The majority of file events occurred on what date? (MONTH DD, YYYY)

- March 25, 2015
- I had to set the scale to linear to see which day had the most. 

![](./Autopsy/2023-05-22-07-51-19.png)



# _**9: Conclusion**_

To conclude, there is more to Autopsy that wasn't covered in detail within this room. Below are some topics that you should explore on your own to configure Autopsy to do more out of the box:

- **Global Hash Lookup Settings**
- **Global File Extension Mismatch Identification Settings**
- **Global Keyword Search Settings**
- **Global Interesting Items Settings**
- **Yara Analyser**

3rd Party [modules](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/module_install_page.html) are available for Autopsy. Visit the official SleuthKit GitHub repo for a list of 3rd party modules [here](https://github.com/sleuthkit/autopsy_addon_modules). The disk image used with this room's development was created and released by the **NIST** under the **Computer Forensic Reference Data Sets** (**CFReDS**) **Project**. It is encouraged to download the disk image, go through the full exercise ([here](https://www.cfreds.nist.gov/data_leakage_case/data-leakage-case.html)) to practice using Autopsy, and level up your investigation techniques. 

Now, we invite you to complete the Autopsy challenge room: [**Disk Analysis & Autopsy**](https://tryhackme.com/room/autopsy2ze0).

Also, if you would like to extend your knowledge in the "Windows Forensics" domain, make sure you visit the following rooms on **THM**:  

- [**Windows Forensics 1**](https://tryhackme.com/room/windowsforensics1)
- [**Windows Forensics 2**](https://tryhackme.com/room/windowsforensics2)  
    

Answer the questions below

Proceed to the given challenge room.  
[Disk Analysis & Autopsy](https://tryhackme.com/room/autopsy2ze0)