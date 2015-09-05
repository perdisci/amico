import unittest
import json

import vt_api


# Create config.py and fill in vt_keys before using this unit test

class TestVtApi(unittest.TestCase):
    def test_get_vt_report(self,):
        md5_hash = "86b6c59aa48a69e16d3313d982791398"
        json_str = vt_api.get_vt_report(md5_hash)
        json_obj = json.loads(json_str)
        self.assertGreater(int(json_obj["positives"]), 40)

    def test_send_file(self,):
        md5_hash = "7e12aac345487d48005d323bae3316f1"
        sample_file = open('../tests/unittest_files/sample_file.txt', 'rb').read()
        json_str = vt_api.send_file(md5_hash, sample_file)
        json_obj = json.loads(json_str)
        print json_obj
        self.assertEqual(int(json_obj["response_code"]), 1)

if __name__ == '__main__':
    unittest.main()

