## Overview of AMICO's Code ##

AMICO's code is currently in 2 directories.

  * **pe\_dump**: This implements the **Download Reconstruction** module. Stores on disk the reconstructed HTTP flows that carry a PE files into a "raw" format.

  * **amico\_scripts**: A chain of scripts that collect partial ground truth using virus total, extract feature vectors, do the online classification using the model and finally generate syslog alerts.

> A brief description of some of the files in amico\_scripts:

  1. `config.py`: The configuration file for the database information
  1. `db_setup.py`: Creates the **Download History** database tables for pe\_dump using `config.py`
  1. `db_cleanup.py`: Drops the tables created by `db_setup.py`
  1. `start_amico.py`: Uses `pe_extract.py`, `db_pe_dumps.py` to move, parse and store the reconstructed PE files. Also, it stores the PE files in a directory named "pe\_files" and the raw files output by `pe_dump.c` in a directory named `raw_files`.
  1. `db_pe_dumps.py`: Parses the PE files stored in the raw files, and creates the related entries in the Download History database.
  1. `db_virus_total.py`: Makes queries to the [VirusTotal](http://www.virustotal.com) database about the reconstructed PE files, and stores the resulting information in the `virus_total_scans` table within the download history database.
  1. `pe_extract.py`: Extracts PE files by stripping the raw files output by `pe_dump.c`
  1. `trainer.py`: A script used to generate the classifier model using the data in the DB.