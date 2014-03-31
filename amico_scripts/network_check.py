import time
import subprocess
import os

DEVNULL = open(os.devnull, 'wb')
tunnel_exists = True
while True:
    #return_code = subprocess.call("ps aux | grep 'ferrari'| grep"
    return_code = subprocess.call("ps aux |"
            "grep 'ssh -fND localhost:12345 ferrari'| grep"
            " -v grep", shell=True, stdout=DEVNULL)
    if return_code == 0:
        tunnel_exists = True
    else:
        tunnel_exists = False
        print "No tunnel found. Sending notification email..."
        subprocess.call(
            "ssh -p 2200 mailer@128.192.76.179 'python email_script.py'",
            shell=True)
    if tunnel_exists:
        time.sleep(60)
    else:
        time.sleep(2 * 60 * 60)
