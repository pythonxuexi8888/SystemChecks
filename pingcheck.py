import sys
import os
import subprocess
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import time


class colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


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
    <b>%s : No response from host or ping failed to %s</b>
    </p>
    </body>
    </html>
    """% (dateandtime, line)

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
    args2 = ["ping", "-c", "1", "-q", line]
    ret_code = subprocess.call(args,
        stdout = open(os.devnull, 'w'),
        stderr = open(os.devnull, 'w')
    )
    p = subprocess.Popen(
        args2,
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE
    )

    out, error = p.communicate()
    #print str(re.findall(r"\' '% packet loss[\w]*", out))
    #print str(re.findall('\[received,\]\s?(.+?)\s?\[packet loss\]', out))
    #packet = ostr(re.findall('\[received,\]\s?(.+?)\s?\[packet loss\]', out))
    out = str(out)
    packet = out.rsplit('received,', 1)[1]
    packets = packet.rsplit(', time', 1)[0]

    if not packets:
        packets = "packets loss missing"

    if ret_code == 0:
        print colors.OKGREEN + "ping to", line, "is OK" , packets + colors.ENDC
        logalerts("Ping to %s is OK %s"% (line, packets))
    elif ret_code == 2:
        print colors.FAIL + "no response from", line, packets + colors.ENDC
        email_critical(line)
        logalerts("No response from %s %s"% (line, packets))
    else:
        print colors.FAIL + "Ping to", line, "failed", packets + colors.ENDC
        email_critical(line)
        logalerts("Ping to %s is failed %s"% (line, packets))

hostsFile.close()
