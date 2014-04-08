from datetime import timedelta, date, datetime
import psycopg2.extras
import psycopg2.extensions
import subprocess
import sys
import os

from train_config import training_days, training_start_date
from features import features
import util


class Trainer:
    def __init__(self,):
        self.output_file = "train.arff"
        self.conn = util.connect_to_db()
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)
        self.clean_label_delta = timedelta(days=30)
        self.training_end_date = date.today()
        if training_start_date:
            self.training_start_date = datetime.strptime(training_start_date,
                    "%Y-%m-%d")
        else:
            cursor = self.conn.cursor()
            cursor.execute("""
                    SELECT MIN(timestamp)
                    FROM pe_dumps""")
            if cursor.rowcount > 0:
                self.training_start_date = cursor.fetchone()[0].date()
            else:
                print "No entries in the database to train!"
                sys.exit()
            cursor.close()
        if training_days:
            self.training_end_date = (self.training_start_date +
                    timedelta(days=training_days))
        print "Training start date:", self.training_start_date.strftime("%B %d, %Y")
        print "Training end date:", self.training_end_date.strftime("%B %d, %Y")

    def count(self,):
        self.benign_dumps = self.get_benign_dumps()
        self.malicious_dumps = self.get_malicious_dumps()
        print "# benign dumps", len(self.benign_dumps)
        print "# malware dumps", len(self.malicious_dumps)

    def train(self,):
        model_name = datetime.today().strftime("%b%d_%y_%H%M%S")
        model_output_file = "models/%s.model" % (model_name,)
        self.benign_dumps = self.get_benign_dumps()
        self.malicious_dumps = self.get_malicious_dumps()
        print "# benign dumps", len(self.benign_dumps)
        print "# malware dumps", len(self.malicious_dumps)
        self.print_arff()
        subprocess.call("""
            java -Xmx2000m -cp ./weka.jar weka.classifiers.meta.FilteredClassifier -t train.arff -d %s -p 1,58,59 -distribution -F "weka.filters.unsupervised.attribute.RemoveType -T string" -W weka.classifiers.trees.RandomForest -- -K 0 -S 1 -I 50 > logs/training/%s.log
            """ % (model_output_file, model_name), shell=True)
        print "New model trained: %s" % (model_output_file,)
        print "Log file: logs/training/%s.log" % (model_name,)
        os.remove("train.arff")

    def get_arff_line(self, dump_id, is_benign):
        self.cursor = self.conn.cursor(
                cursor_factory=psycopg2.extras.NamedTupleCursor)
        values = []
        self.cursor.execute("""
            SELECT * FROM weka_features
            WHERE dump_id = %s""",
            (dump_id, ))
        if self.cursor.rowcount == 0:
            return
        res = self.cursor.fetchone()
        res = res._asdict()
        for feature in features:
            values.append(res[feature])
        try:
            data_string = ','.join(['?' if value is None else
                str(value) for value in values])
        except Exception as e:
            print "Error in generating the feature vector in ARFF", e
            return
        if is_benign:
            data_string += ",neg"
        else:
            data_string += ",pos"
        self.cursor.close()
        return data_string

    def print_arff(self,):
        w = open(self.output_file, 'w')
        w.write('@RELATION train\n\n')
        for feature in features:
            if feature in ['sha1', 'dump_id', 'host', 'corrupt',
                    'vt_month_shelf', 'url_struct']:
                data_type = "STRING"
            elif feature == "extension_class":
                data_type = ("{common_ext,unknown_ext,common_fake,other_ext,"
                       "no_url,no_ext}")
            else:
                data_type = "NUMERIC"
            w.write('@ATTRIBUTE %s %s\n' % (feature, data_type))
            #print "%s : %s" % (key, res[key])

        w.write('@ATTRIBUTE class {pos, neg}\n\n')
        w.write('@DATA\n\n')
        for dump_id in self.benign_dumps:
            arff_line = self.get_arff_line(dump_id, True)
            if arff_line:
                w.write(arff_line + '\n')
        for dump_id in self.malicious_dumps:
            arff_line = self.get_arff_line(dump_id, False)
            if arff_line:
                w.write(arff_line + '\n')
        w.close()

    def get_benign_dumps(self,):
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            SELECT DISTINCT(sha1)
            FROM
                virus_total_scans as vts JOIN
                virus_total_submissions as vt_sub
                USING (sha1)
            WHERE
                vt_sub.scan_time - vts.scan_time > %s
                AND vt_sub.num_av_labels = 0
            """, (self.clean_label_delta,))
        hashes = set(self.cursor.fetchall())
        self.cursor.execute("""
            SELECT DISTINCT(sha1)
            FROM
                virus_total_submissions as vts JOIN
                virus_total_submissions as vt_sub
                USING (sha1)
            WHERE
                vt_sub.scan_time - vts.scan_time > %s
                AND vt_sub.num_av_labels = 0
            """, (self.clean_label_delta,))
        hashes.update(self.cursor.fetchall())
        dumps = set()
        for sha1 in hashes:
            self.cursor.execute("""
                SELECT dump_id
                FROM pe_dumps
                WHERE timestamp >= %s AND
                timestamp <= %s AND
                sha1 = %s
                """, (self.training_start_date, self.training_end_date,
                    sha1))
            dumps.update(self.cursor.fetchall())
        self.cursor.close()
        return dumps

    def get_malicious_dumps(self,):
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            SELECT DISTINCT(sha1)
            FROM
                virus_total_scans as vts JOIN
                virus_total_submissions as vt_sub
                USING (sha1)
            WHERE
                vt_sub.scan_time - vts.scan_time > %s
                AND vt_sub.trusted_av_labels >= 2
            """, (self.clean_label_delta,))
        hashes = set(self.cursor.fetchall())
        self.cursor.execute("""
            SELECT DISTINCT(sha1)
            FROM
                virus_total_submissions as vts JOIN
                virus_total_submissions as vt_sub
                USING (sha1)
            WHERE
                vt_sub.scan_time - vts.scan_time > %s
                AND vt_sub.trusted_av_labels >= 2
            """, (self.clean_label_delta,))
        hashes.update(self.cursor.fetchall())
        dumps = set()
        for sha1 in hashes:
            self.cursor.execute("""
                SELECT dump_id
                FROM pe_dumps
                WHERE timestamp >= %s AND
                timestamp <= %s AND
                sha1 = %s
                """, (self.training_start_date, self.training_end_date,
                    sha1))
            dumps.update(self.cursor.fetchall())
        self.cursor.close()
        return dumps

if __name__ == "__main__":
    trainer = Trainer()
    if len(sys.argv) > 1 and sys.argv[1] == "-c":
        trainer.count()
    else:
        trainer.train()
