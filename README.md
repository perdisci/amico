# Overview #

**AMICO** is a malware download classification tool that can be deployed in large networks. It reconstructs executable files (Windows PE files, but now also JARs, DMGs, APKs, and ELFs) from the network traffic and determines if they are malicious or not based on their _provenance information_.

To classify an executable file download event, AMICO looks at **who** is downloading **what** and from **where**, rather than analyzing the content of the downloaded files.

For more technical information, please refer to this [ESORICS 2013 research paper](http://www.perdisci.com/publications/publication-files/amico.pdf)

For more information on how to use and deploy AMICO, please go through the Wiki pages. This is an initial release of the system and we will keep refining the code and documentation. Please open a new Issue if you experience any problems.

You can also visit our [AMICO-Security Blog](http://amico-security.blogspot.com/).


## SETUP AND DEPLOYMENT ##
Please refer to our [project's Wiki](https://github.com/perdisci/amico/wiki) for detailed information about system requirements, setup, and deployment guidelines.


## CONTACT US ##
If you have any questions, please post a message on our [AMICO-security forum](https://groups.google.com/forum/#!forum/amico-security).

If you are deploying AMICO in a large _university-like campus network_ and would like to share your experience or know more about our own deployment, please contact us privately at (**perdisci [-at-] cs.uga.edu**).


## LICENSING ##
The code under the "master" branch is released under BSD license. Please refer to the COPYING file under the master branch for details.

Notice that code in other directories, such as "tags/amico-1.0" and "branches/experimental", is currently released under GNU GPL.


## News ##
  * [01/11/2016] Enabled submission of file types other than EXE to VirusTotal (in the experimental branch only).
  * [04/29/2015] Improved [experimental branch code](https://github.com/perdisci/amico/tree/experimental), and tested capture and classification of APKs and JARs in a large network.
  * [03/27/2015] All code in the master branch has been released under **BSD license**.
  * [03/27/2015] Moved all project files from GoogleCode to GitHub.
  * [01/14/2015] Added some documentation about [syslog reports format](https://github.com/perdisci/amico/wiki/Syslog-Reports-Format).
  * [11/20/2014] Added experimental code for supporting file formats other than Windows PE (see svn/branches/experimental). We can currently extract most JAR, APK, DMG, ZIP, RAR, PDF files, and even some Microsoft Office documents. _Limitations_: the feature extraction and provenance classifier currently treat all file types the same way; we are performing more research to see if the behavior-based detection approach used by AMICO can still work well even with non-executable files.
  * [11/08/2014] We have created the [AMICO-Security Blog](http://amico-security.blogspot.com/), where we discuss malware campaign discoveries and other related topics.
  * [10/09/2014] Quick steps for [tuning packet capture](https://github.com/perdisci/amico/wiki/Tuning-Packet-Capture) and drastically reduce packet loss.
  * [10/03/2014] Added a brief [example of how AMICO can be deployed](https://github.com/perdisci/amico/wiki/Deployment-Example) in a network.
  * [09/15/2014] We recently fixed a number of rarely-triggered bugs and improved general code quality and stability.
  * [09/13/2014] In the Wiki, you can now find more information about the [pe\_dump](https://github.com/perdisci/amico/wiki/pe_dump-Module) component of AMICO.
  * [08/26/2014] We successfully built a PF\_RING-aware version of AMICO (see [how we did it](https://github.com/perdisci/amico/blob/master/external_libs/README))
