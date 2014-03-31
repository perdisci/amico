#!/bin/bash

ps ax|grep kill_hanged_gsb_queries|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep kill_hanged_manual_downloads|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep kill_hanged_vtqueries|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep manual_download|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep gsb_cron|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep vt_cron|grep -v grep|awk '{print $1}'|xargs kill
ps ax|grep process_dump|grep -v grep|awk '{print $1}'|xargs kill

