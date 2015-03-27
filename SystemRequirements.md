We tested AMICO on **Debian Squeeze, Wheezy and Ubuntu 12.04**.
The following packages and libraries are needed for all modules to work properly:

  * libpcap0.8-dev (or later)
  * python 2.6 (or later; will probably _not_ work with python 3)
  * libbind-dev
  * ethtool 2.6.34 (or later)
  * PostgreSQL 8.4.9 (or later)
  * python-psycopg2 (version 2.4.2 or later)
  * python-socksipy
  * python-simplejson
  * python-numpy
  * sun-java6-jre (or later; needed to run the Weka-based provenance classifier)
  * Weka (available from http://www.cs.waikato.ac.nz/ml/weka/downloading.html)
  * dig - DNS lookup utility (this should be installed by default, but it's better to double check)

For **RedHat** users (based on feedback from Jesse Bowling):

it seems that installing `python-socksipy` may be problematic for some versions of RH Linux. If that's the case, you can use the following workaround:

  1. go to the `amico_scripts` directory
  1. edit `util.py` and `ip2asn.py` and comment out `import socks`

As long as `socks_proxy_host = None` in your `amico_scripts/config.py` file (meaning you do not need to proxy your queries to VirusTotal, for example), you should be able to run AMICO without `python-socksipy`.