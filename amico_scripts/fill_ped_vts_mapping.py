"""
A script to fill the ped_vts_mapping table
"""
import util

MIN_DUMP_ID = 1
MAX_DUMP_ID = 188100
OVERWRITE_IF_EXISTS = False  # Overwrite if the row already exists


def main():
    conn = util.connect_to_db()
    cursor = conn.cursor()

    cursor.execute("""
            DROP TABLE IF EXISTS ped_vts_mapping_temp
            """)
    cursor.execute("""
            CREATE TABLE ped_vts_mapping_temp
            (LIKE ped_vts_mapping) """)
    cursor.execute("""
        INSERT INTO ped_vts_mapping_temp
        (SELECT dump_id, MAX(vt_id) AS vt_id
         FROM pe_dumps AS pe join virus_total_scans AS vt
             using(sha1)
         WHERE vt.query_time < (pe.timestamp + '1 hour')
               AND dump_id >= %s AND dump_id <= %s
         GROUP by dump_id)""",
         (MIN_DUMP_ID, MAX_DUMP_ID))
    cursor.execute("""
        DELETE FROM ped_vts_mapping_temp
        WHERE vt_id is NULL""")

    if OVERWRITE_IF_EXISTS:
        cursor.execute("""
            DELETE FROM ped_vts_mapping
            WHERE dump_id >= %s AND dump_id <= %s""",
            (MIN_DUMP_ID, MAX_DUMP_ID))

    cursor.execute("""
        DELETE FROM ped_vts_mapping_temp
        WHERE dump_id in (
              SELECT dump_id
              FROM ped_vts_mapping)""")
    cursor.execute("""
        INSERT INTO ped_vts_mapping(
            SELECT * from ped_vts_mapping_temp)""")

    cursor.execute("""
        DROP TABLE ped_vts_mapping_temp""")

if __name__ == "__main__":
    main()
