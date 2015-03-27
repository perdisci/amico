AMICO logs its detection results both to a database and via syslog. Here we describe the format of the log entries in syslog:

Example syslog entry:
```
Jan 14 09:28:26 netbox1 start_amico.py: PE file download -- 
timestamp: 2015-01-14 09:21:16, 
client_ip: 10.21.7.3, 
server_ip: 23.73.181.26, 
server_port: 80, 
host: install-cdn.solutionreal.com, 
url: /ud, 
referrer: None, 
sha1: 59a2bddd377ad76a16155bcb86fa56f6b3e60b1c, 
md5: 3bc57ac01a542276a51a6666aba375b6, 
file_size: 548600, 
av_labels: 9, 
corrupt: False, 
amico_score: MALWARE#0.833#0.4
```

Here is an explanation of the non-obvious fields:

  * `av_labels`: if `None` it means that the file hash was not "known" to VirusTotal at the time of download. Otherwise, it reports the number of AV labels found on VirusTotal.
  * `corrupt`: if `True`, it means that the reconstructed binary may be corrupted (e.g., due to packet loss, TCP RST, etc.)
  * `amico_score`: indicates AMICO's classification output, with the following format: `LABEL#CLASSIFIER_SCORE#SCORE_THRESHOLD`; the label is set to `MALWARE` if `CLASSIFIER_SCORE>SCORE_THRESHOLD`, otherwise it is set to `BENIGN`

Notice that the most important piece of information is the actual score produced by the classifier (0.833 in the above example). Our default detection threshold is set to 0.4 because we empirically found it to produce a good trade-off between true detections and false positives.

Of course, you could decide that for your organization it is better to focus on download events that exceed  a score of, say, 0.7, instead of relying on our default threshold of 0.4. The higher the threshold you choose, the fewer the false positives you can expect to see. But naturally, if you filter out logs that have a score below 0.7 you may also miss some possible malware download events. So, we suggest to use the score as a way of prioritizing the analysis and visualization of the most malicious downloads.

The good thing is that Amico reports **all** download events it observes, so you can always go back to the logs, and also to the download history database whenever needed.