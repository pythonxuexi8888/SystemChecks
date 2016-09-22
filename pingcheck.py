import sys
import os
import subprocess
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import time

NOW = time.strftime("%c")
dateandtime = time.strftime("%c")
update = " "

def logalerts(update):
    logfile = '/var/log/pingtest.log'
    wrtite2file = open(logfile, 'a')
    if not update:
        STAUTS="INFO"
    else:
        print >>wrtite2file,dateandtime, update


def email_critical(line):
    sender = "srinivas.ashok@itaas.dimensiondata.com"
    receivers = "srinivas.ashok@itaas.dimensiondata.com,niraj.kumar@dimensiondata.com,ramesh.sharma@itaas.dimensiondata.com"

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receivers
    msg['Subject'] = "CRITICAL: JNB01 PING test results"
    body = """
    <html>
    <body>
    <p>
    <font size="4" face="Courier" color="red">
    <b>No response from host or ping failed to %s</b>
    </p>
    </body>
    </html>
    """% (line)

    try:
        msg.attach(MIMEText(body, 'html'))
        server = smtplib.SMTP('localhost')
        text = msg.as_string()
        server.sendmail(sender, receivers, text)
        server.quit()
    except smtplib.SMTPException:
        print ("Error: unable to send email")


scriptDir = sys.path[0]
hosts = os.path.join(scriptDir, 'hosts.txt')
hostsFile = open(hosts, "r")
lines = hostsFile.readlines()
for line in lines:
    line = line.strip( )
    args = ["ping", "-c", "1", "-l", "1", "-s", "1", "-W", "1", line]
    ret_code = subprocess.call(args,
        stdout = open(os.devnull, 'w'),
        stderr = open(os.devnull, 'w')
    )
    if ret_code == 0:
        print "ping to", line, "is OK"
        logalerts("Ping to %s is OK"% (line))
    elif ret_code == 2:
        print "no response from", line
        email_critical(line)
        logalerts("No response from %s"% (line))
    else:
        print "Ping to", line, "failed"
        email_critical(line)
        logalerts("Ping to %s is failed"% (line))

hostsFile.close()
