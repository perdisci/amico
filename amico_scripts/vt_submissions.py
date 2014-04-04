###########################################################################
# Copyright (C) 2011-2013 Phani Vadrevu and Roberto Perdisci              #
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

import sys
from datetime import timedelta, date
import time

import simplejson
import logging
import logging.config

from config import *
import vt_api
import util

LOG_CONF_FILE = "logging.conf"

class VTSubmissions:
    def __init__(self):
        self.QUERY_RATE_LIMIT = 10
        self.ONE_MIN = 60

        logging.config.fileConfig(LOG_CONF_FILE)
        self.logger = logging.getLogger("amico_logger")
        #stdout_handler = logging.StreamHandler(sys.stdout)
        #stdout_handler.setLevel(logging.DEBUG)
        #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s'
                               #'- %(message)s')
        #stdout_handler.setFormatter(formatter)
        #self.logger.addHandler(stdout_handler)

        util.setup_socks()
        self.conn = util.connect_to_db()
        self.cursor = self.conn.cursor()

        self.today = date.today().strftime("%Y-%m-%d")
        self.yesterday = (date.today() -
                timedelta(days=1)).strftime("%Y-%m-%d")
        self.last_month = (date.today() -
                timedelta(days=30)).strftime("%Y-%m-%d")

    def get_hashes_from_db(self):
        if vt_submissions == "manual":
            hashes = self.get_hashes_from_db_manual()
        elif vt_submissions == "live":
            hashes = self.get_hashes_from_db_live()
        else:
            hashes = self.get_hashes_from_db_scans()
        self.hashes = self.update_hashes(hashes)

    def update_hashes(self, hashes):
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM virus_total_submissions
            WHERE (submit_time::date) = %s
            """, (self.last_month,))
        if self.cursor.rowcount > 0:
            hashes = hashes.union(self.cursor.fetchall())
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM virus_total_submissions
            WHERE (submit_time::date) > %s AND
            (submit_time::date) < %s
            """, (self.last_month, self.yesterday))
        if self.cursor.rowcount > 0:
            hashes = hashes.difference(self.cursor.fetchall())
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM virus_total_submissions
            WHERE (submit_time::date) = %s
            """, (self.today,))
        if self.cursor.rowcount > 0:
            hashes = hashes.difference(self.cursor.fetchall())
        self.logger.debug("submit_hashes(): Number of hashes: %s", len(hashes))
        return hashes

    def get_hashes_from_db_scans(self):
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM virus_total_scans
            WHERE json IS NOT NULL AND
            query_time::date = %s
            """, (self.yesterday,))
        if self.cursor.rowcount > 0:
            hashes = set(self.cursor.fetchall())
        else:
            hashes = set()
        return hashes

    def get_hashes_from_db_live(self):
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM pe_dumps
            WHERE sha1 IS NOT NULL AND
            timestamp::date = %s
            """, (self.yesterday,))
        if self.cursor.rowcount > 0:
            hashes = set(self.cursor.fetchall())
        else:
            hashes = set()
        return hashes

    def get_hashes_from_db_manual(self):
        self.logger.debug("entered get_hashes_from_db_manual()")
        self.cursor.execute("""
            SELECT distinct md5, sha1
            FROM manual_download_checksums
            WHERE referer_exists = 'f' AND
            sha1 IS NOT NULL AND
            timestamp::date = %s
            """, (self.yesterday,))
        if self.cursor.rowcount > 0:
            hashes = set(self.cursor.fetchall())
        else:
            hashes = set()
        return hashes

    def insert_scan(self, sha1, md5, response):
        self.logger.debug("entered insert_scan()")
        self.cursor.execute("""
            INSERT INTO virus_total_submissions
            (submit_time, sha1, md5, scan_id)
            VALUES (LOCALTIMESTAMP, %s, %s, %s)
            RETURNING vt_submit_id
            """, (sha1, md5, response['scan_id']))
        vt_submit_id = self.cursor.fetchone()[0]
        self.cursor.execute("""
            UPDATE virus_total_submissions
            SET resubmit_id = %s
            WHERE sha1= %s AND
            submit_time::date = %s
            """, (vt_submit_id, sha1, self.last_month))

    def check_report_exists(self, sha1):
        self.cursor.execute("""
            SELECT * FROM virus_total_scans
            WHERE sha1 = %s AND
            scan_time IS NOT NULL""", (sha1, ))
        report_exists = True if self.cursor.rowcount else False
        self.cursor.execute("""
            SELECT * FROM virus_total_submissions
            WHERE sha1 = %s AND
            json IS NOT NULL""", (sha1, ))
        report_exists = True if self.cursor.rowcount else report_exists
        return report_exists

    def make_request(self, md5, sha1):
        self.logger.debug("entered make_request()")
        self.logger.debug("sha1: %s", sha1)
        report_exists = self.check_report_exists(sha1)
        self.logger.debug("report_exists: %s", report_exists)
        json = None
        try:
            json = (vt_api.rescan_request(md5) if report_exists else
                    vt_api.send_file(md5))
            if json:
                response = simplejson.loads(json)
                if response["response_code"] == 1:
                    self.insert_scan(sha1, md5, response)
                    return True
                else:
                    self.logger.warning("make_request: Bad response code: %s",
                                            response["response_code"])
            else:
                self.logger.warning("make_request: No JSON response")
        except Exception as e:
            self.logger.exception("report_exists: %s", report_exists)
            self.logger.exception("json: %s", json)
            self.logger.exception("sha1: %s", sha1)
            self.logger.exception("make_request: Error %s", e)
        return False

    def submit_hashes(self):
        self.logger.debug("entered submit_hashes()")
        query_count = 0
        done_hashes = set()
        for md5, sha1 in self.hashes:
            tries = 0
            # This loop makes max 3 attempts to send a scan request
            while tries <= 3:
                if query_count == self.QUERY_RATE_LIMIT:
                    self.logger.debug(
                        "Query limit reached. Sleeping for a min.")
                    time.sleep(self.ONE_MIN)
                    query_count = 0
                tries += 1
                query_count += 1
                if self.make_request(md5, sha1):
                    done_hashes.add((md5, sha1))
                    break
        if len(self.hashes):
            self.logger.debug("Submitted the hashes on: %s", date.today())
        self.hashes.difference_update(done_hashes)

    def update_table_with_report(self, scan_id, report, json):
        self.logger.debug("entered update_table_with_report()")
        scan_time = report["scan_date"]
        scans = report["scans"]
        num_av_labels = report["positives"]
        trusted_av_labels = 0
        for k, v in scans.iteritems():
            if v["detected"] is True:
                if k in trusted_av_vendors:
                    trusted_av_labels += 1
        scan_time += " UTC"
        self.cursor.execute("""
            UPDATE virus_total_submissions
            SET trusted_av_labels = %s,
            num_av_labels = %s,
            scan_time = TIMESTAMP WITH TIME ZONE %s,
            json = %s
            WHERE scan_id = %s and json is NULL""",
            (trusted_av_labels, num_av_labels, scan_time,
             json, scan_id))

    def fetch_reports(self):
        self.logger.debug("entered fetch_reports()")
        self.cursor.execute("""
            SELECT scan_id
            FROM virus_total_submissions
            WHERE json is NULL and
            (LOCALTIMESTAMP - submit_time) > '5 minutes' and
            (LOCALTIMESTAMP - submit_time) < '3 days'
            ORDER BY submit_time ASC""")
        scan_ids = [row[0] for row in self.cursor.fetchall()]
        self.logger.debug("fetch_reports(): %s scan reports to be fetched",
                len(scan_ids))
        query_count = 0
        for scan_id in scan_ids:
            if query_count == self.QUERY_RATE_LIMIT:
                self.logger.debug(
                    "Query limit reached. Sleeping for a min.")
                time.sleep(self.ONE_MIN)
                query_count = 0
            query_count += 1
            try:
                json = vt_api.get_vt_report(scan_id)
                if not json:
                    self.logger.debug("No json")
                    continue
                report = simplejson.loads(json)
                # Sometimes, we get the old reports wrongly
                if (report["response_code"] != 1) or (
                        report['scan_id'] != scan_id):
                    self.logger.debug("Response code %s for scan_id %s" %
                            (report["response_code"], scan_id))
                    continue
                self.update_table_with_report(scan_id, report, json)
            except Exception as e:
                self.logger.exception(
                  "Error in fetching report for scan_id %s: %s" % (scan_id, e))
                continue


def sleep_for_the_day():
    today = date.today()
    while today == date.today():
        time.sleep(15 * 60)


def vt_submissions():
    vt_submit = VTSubmissions()
    vt_submit.get_hashes_from_db()
    while True:
        try:
            vt_submit.submit_hashes()
            vt_submit.fetch_reports()
        except Exception as e:
            vt_submit.logger.exception(
                "Unexpected error! %s \n Sleeping for the rest of the day", e)
            sleep_for_the_day()

        vt_submit.logger.debug("main(): Sleeping for 15 min.")
        time.sleep(vt_submit.ONE_MIN * 15)

        today = date.today().strftime("%Y-%m-%d")
        if today != vt_submit.today:
            vt_submit.today = today
            vt_submit.yesterday = (date.today() -
                    timedelta(days=1)).strftime("%Y-%m-%d")
            vt_submit.last_month = (date.today() -
                    timedelta(days=30)).strftime("%Y-%m-%d")
            vt_submit.get_hashes_from_db()


if __name__ == "__main__":
    vt_submissions()
