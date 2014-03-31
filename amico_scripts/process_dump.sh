#!/bin/bash
###########################################################################
# Copyright (C) 2011 Phani Vadrevu                                        #
# pvadrevu@uga.edu                                                        #
#                                                                         #
# Distributed under the GNU Public License                                #
# http://www.gnu.org/licenses/gpl.txt                                     #   
#                                                                         #
# This program is free software; you can redistribute it and/or modify    #
# it under the terms of the GNU General Public License as published by    #
# the Free Software Foundation; either version 2 of the License, or       #
# (at your option) any later version.                                     #
#                                                                         #
###########################################################################


# Wait time between iterations of the while loop
WAIT_TIME=1

# Print usage if 2 arguments have not been passed
if [ "$1" == "" ]
then
	echo "Usage: ./process_dump.sh dump_dir [target_dir]"
	echo "target_dir should be an absolute path"
	exit
fi

dump_dir=$1
target_dir=$2

# Specify a target_dir if not given by user
if [ "$2" == "" ]
then
	target_dir="$PWD/parsed"
	echo "Created a target directory: $target_dir"
fi

# Create raw_files and pe_files directories in target_dir
# if required
mkdir -p $target_dir
mkdir -p $target_dir/raw_files
mkdir -p $target_dir/pe_files

# Create dir for storing manual downloads
mkdir -p $PWD/manual_downloads

python vt_submissions.py >& $PWD/logs/vt_api.log &

# this is necessary because sometimes the VT API hangs and waists lost of CPU
./kill_hanged_vtqueries.sh >& /dev/null &
./kill_hanged_manual_downloads.sh >& /dev/null &

# start monitoring for dumps...
while true
do
	dumped_files=`ls -atr $dump_dir|egrep "\:[0-9]+\-[0-9]+$" | egrep -v "\.tmp$"`	

    # Process each file if it is not in the list of open files	
	for i in $dumped_files; do
		mv -f $dump_dir/$i $target_dir

        # here we do some quick witelisting
        # it would be much better to do this in Python and verify that Host has not been forged via passive DNS
        host=$(head -n6 $target_dir/$i | egrep "% Host: (.{1,20}\.(windowsupdate|avg|microsoft|google|apple|adobe)\.com|se.360.cn)")


        if [ -z "$host" ]; then
            python pe_extract.py $target_dir/$i

            sha1=`sha1sum $target_dir/$i.exe`
            sha1=${sha1:0:40}
            md5=`md5sum $target_dir/$i.exe`
            md5=${md5:0:32}
            file_size=`ls -l $target_dir/$i.exe|awk '{print $5}'`

            if [ -n "$sha1" ]; then	
                out=`python db_pe_dumps.py $target_dir/$i $sha1 $md5 $file_size`
                dump_id=`echo $out|cut -d' ' -f 14`
                echo "The dump_id is: $dump_id"
                # checks if the file is corrupt
                corrupt=$(head -n6 $target_dir/$i | egrep "% CORRUPT_PE")

                if [ -z "$corrupt" ]; then
                    python db_virus_total.py $dump_id
                fi

                python manual_download.py $sha1 &
                python ip2asn.py $sha1
                
                if [ -z "$corrupt" ]; then
                     python get_feature_vector.py $dump_id
                     python classify_dump.py $dump_id
                     python db_syslog.py $dump_id
                fi
                mv -f $target_dir/$i $target_dir/raw_files/
                mv -f $target_dir/$i.exe $target_dir/pe_files/$sha1.exe
                ln -s $target_dir/pe_files/$sha1.exe $target_dir/pe_files/$md5.exe

                echo -e "The file: $i has been moved and processed\n"
            else
                rm -f $target_dir/$i
            fi
        else
            rm -f $target_dir/$i
        fi
	done
		
	# echo ${open_files[@]}
	
	# echo "============================================"
	sleep $WAIT_TIME
done
