import unittest

import vt_api


# Create config.py and fill in vt_keys before using this unit test

class TestVtApi(unittest.TestCase):

    def test_get_vt_report(self,):
        hash = "86b6c59aa48a69e16d3313d982791398"
        print vt_api.get_vt_report(hash)


if __name__ == '__main__':
    unittest.main()