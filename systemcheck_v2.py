#!/usr/bin/python

""" Importing required python modules from the python library
"""

from optparse import OptionParser
import os
import sys
import socket
import platform
from datetime import datetime
import subprocess
from time import sleep
import logging
import urllib2

formats = "[%(levelname)s] %(message)s"
logging.basicConfig(format=formats, level=logging.INFO)
logger = logging.getLogger(__name__)

""" Usage: [ options ] for the command line arguments pass
"""

parser = OptionParser()
parser.add_option("-d", "--dcname", dest='dc information', action='store_true', default=False, help='Provide the dc name, EX: python %s --dcname AU' %sys.argv[0])
(options, args) = parser.parse_args()

def Help():
    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)
Help()

""" Defined Global Variables
"""

host = socket.gethostname()
progname = sys.argv[0]
#osvers = platform.linux_distribution()[1].split('.')[0]
osvers = platform.dist()[1].split('.')[0]

NOW = datetime.now()
MONTH = NOW.month
DAY = NOW.day
YEAR = NOW.year

""" Defined two dictionary to map the Time Zone based on each Data Center and to get a Month of the year in number
"""

DCTZ = {"AF": 'SAST', "AP": 'JST', "AU": 'AEST', "CA": 'EDT', "AC": 'AEST',
        "EU": 'CEST', "IN": 'IST', "ID": 'WIB', "IL": 'IDT', "NA": 'EDT', "SA": 'BRT'}

GetMonth = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

""" Defined a class and its variables for font colour,
these class variables used in Reporting functions like ReportInfo, ReportWarn, ReportError and ReportDebug below
"""

class colors:

    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

""" Defined a functions to report the STD OUT on your screen
"""

def ReportInfo(info):
    print colors.GREEN + "[INFORMATION]: %s" % (info) + colors.ENDC

def ReportWarn(warn):
    print colors.WARNING + "[WARNING]: %s" % (warn) + colors.ENDC

def ReportError(error):
    print colors.FAIL + "[ERROR]: %s" % (error) + colors.ENDC

def ReportDebug(debug):
    print colors.BLUE + "[DEBUG]: %s" % (debug) + colors.ENDC

""" Defined a function which prompt the script executer to handle or verify the below checks manually
    """

def GeneralInfo():
    C = header()
    C.PrintHeader(" MANUAL ATTENTION REQUIRED ", "            Make sure you are validated below checks", 2)

    ReportWarn("Make sure you update the Hostname,ServerIP and ILO Information in wiki")
    ReportWarn("Make sure you update the root password in CustAuth")
    ReportWarn("Make sure you completed the cluster failure and fencing test if this is cluster")
    ReportWarn("Make sure you configured valid probes or checks at nimsoft server")

""" Prints the header information """

class header:
    def PrintHeader(self, head, comment, wait):
        self.head = head
        self.comment = comment
        self.wait = wait

        header = head
        header = str(header)
        print " "
        print colors.HEADER + header.center(80, '=') + colors.ENDC
        print colors.GREEN + comment + colors.ENDC
        bottom = " ************ "
        bottom = str(bottom)
        print colors.HEADER + bottom.center(80, '=') + colors.ENDC
        print " "
        sleep(wait)


# System checks function starts from here.

""" A Class and method to find the what apps running on server
"""
class GetApps:
    def CheckApps(self):
        apps = {'ccdb': "DB", 'xo': "XOPS"}
        for key, value in apps.iteritems():
            if key in host:
                APPNAME = apps[key]
                return APPNAME

    def PrintApp(self):
        C = GetApps()
        APP = C.CheckApps()
        if APP is None:
            ReportError("The %s is not standard hostname"% host)
        else:
            ReportInfo("This is a %s server" % APP)

""" A function which do ping test to the host
"""
def CheckPing(host):
    ret_code = subprocess.call(['ping', '-c', '5', '-W', '3', host],
                               stdout=open(os.devnull, 'w'),stderr=open(os.devnull, 'w'))
    if ret_code == 0:
        ReportInfo("Ping test success")
    else:
        ReportError("Ping test failed")

""" A function to check the SE linux status
"""
def CheckSELinux():
    p = subprocess.Popen("getenforce", shell=True, stdout=subprocess.PIPE)
    output = p.communicate()[0]
    output = output.strip()

    if output == "Permissive":
        ReportInfo("SE Linux is set to Permissive")
    else:
        ReportError("SE Linux is set to %s"% output)

""" A function which check the port 443 opened for Chef-Server
"""

def CheckPort443():
    port = 443
    HOST = CheckChefCfg()

    if HOST == None:
        HOST = 'ash01chef01p.itaas.dimensiondata.com'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((HOST, port))
        if result == 0:
            ReportInfo("Port 443 to chef-server is enabled")
        else:
            ReportError("Port 443 to chef-server is disabled")
        sock.close()

    except KeyboardInterrupt:
        ReportError("You pressed Ctrl+C,can't check port 443")
        sys.exit()

    except socket.gaierror:
        ReportError("CHECK PORT 443: Hostname could not be resolved,can't check port 443")
        sys.exit()

    except socket.error:
        ReportError("CHECK PORT 443: Couldn't connect to server,can't check port 443")
        sys.exit()


""" A function to check chef-client configurations files
"""

def CheckChefCfg():
    FILE = '/etc/chef/client.rb'
    if os.path.isfile(FILE):
        for line in open(FILE, 'r'):
            if "chef_server_url" in line:
                chef_server = line
                chef_server = chef_server.rstrip()
                chef_server = chef_server.split('"https://')[1]
                chef_server = chef_server.split('/')[0]
        return chef_server
    else:
        ReportWarn("chef-client not configured %s No such file" % FILE)

""" A function to check the chef-client service
"""

def CheckChefRuns():

    if osvers == '5':
        FILE = '/etc/init.d/chef-client'
        if os.path.isfile(FILE):
            CHECK = subprocess.Popen("service chef-client status", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()
            if 'running' in CHECK:
                ReportInfo("chef-client service up and running")
            elif 'stopped' in CHECK:
                ReportError("chef-client service is stopped")
            else:
                ReportDebug("No Info found for chef-client service, please debug")
        else:
            ReportWarn("chef-client not running %s No such file" % FILE)
    elif osvers == '6':
        FILE = '/etc/init.d/chef-client'
        if os.path.isfile(FILE):
            CHECK = subprocess.Popen("service chef-client status", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()
            if 'running' in CHECK:
                ReportInfo("chef-client service up and running")
            elif 'stopped' in CHECK:
                ReportError("chef-client service is stopped")
            else:
                ReportDebug("No Info found for chef-client service, please debug")
        else:
            ReportWarn("chef-client not running %s No such file" % FILE)
    elif osvers == '7':
        CHECK = subprocess.Popen("systemctl is-active chef-client.service", shell=True,stdout=subprocess.PIPE).stdout.read()
        CHECK = CHECK.rstrip()

        if 'inactive' in CHECK:
            ReportError("chef-client service is stopped")
        elif 'active' in CHECK:
            ReportInfo("chef-client service up and running")
        elif 'unknown' in CHECK:
            ReportWarn("chef-client service is not running")
        else:
            ReportDebug("No Info found for chef-client service, please debug")
    else:
        ReportError("CHECK chef-client service: OS version %s does not match" % osvers)


""" A class and its methods to check the Network bonding configurations
"""

class CheckNetBondCfg:

    def BondMasterFile(self):

        BONDGMASFILE = '/sys/class/net/bonding_masters'
        if os.path.exists(BONDGMASFILE):
            f = open(BONDGMASFILE, 'r')
            bond = f.read()
            bond = bond.rstrip()
            bond = bond.split(' ', 1)

            INTERF = []
            CHECKINT = subprocess.Popen("ifconfig -a|grep -i ^bond|awk '{print $1}'|head -1", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECKINT = CHECKINT.rstrip()
            INTERF.append(CHECKINT)
            for inter in INTERF:
                if inter == 'bond0':
                    BONDF = subprocess.Popen("cat /proc/net/bonding/bond0|grep 'Currently Active Slave'", shell=True, stdout=subprocess.PIPE).stdout.read()
                    BONDF = BONDF.rstrip()
                    ReportInfo(BONDF)
                elif inter == 'bond1':
                    BONDF = subprocess.Popen("cat /proc/net/bonding/bond1|grep 'Currently Active Slave'", shell=True, stdout=subprocess.PIPE).stdout.read()
                    BONDF = BONDF.rstrip()
                    ReportInfo(BONDF)
                elif inter == 'bond2':
                    BONDF = subprocess.Popen("cat /proc/net/bonding/bond2|grep 'Currently Active Slave'", shell=True, stdout=subprocess.PIPE).stdout.read()
                    BONDF = BONDF.rstrip()
                    ReportInfo(BONDF)
                elif inter == 'bond3':
                    BONDF = subprocess.Popen("cat /proc/net/bonding/bond3|grep 'Currently Active Slave'", shell=True, stdout=subprocess.PIPE).stdout.read()
                    BONDF = BONDF.rstrip()
                    ReportInfo(BONDF)
                else:
                    ReportDebug("The bond inter faces are not bond0,bond1,bond2,bond3, please debug")
            return bond
        else:
            ReportError("Network bonding is not configured %s not found" % BONDGMASFILE)

    def BondSlaves(self):
        C = CheckNetBondCfg()
        SLAVES = C.BondMasterFile()
        wordcount = []
        if SLAVES is not None:
            ReportInfo("Server configured with %s interfaces" % SLAVES)
            for b in SLAVES:
                f = open("/sys/class/net/%s/bonding/slaves" % b, 'r')
                for line in f:
                    wordcount.append(line.split(None, 1))
                    if len(wordcount) == 2:
                        ReportInfo("Network bonding slaves cnfiguration is correct in %s" % b)
                    elif len(wordcount) > 2:
                        ReportInfo("Network bonding has more than 2 slaves in %s" % b)
                    elif len(wordcount) == 1:
                        ReportWarn("One network interface is missing in %s network config" % b)
                    else:
                        ReportError("Network bond slaves not found")
        else:
            ReportError("No bond interfaces found from ifconfig")


""" A function to check the last patch update on the server
"""

def CheckPatchUpdate():

    RPMDAY = subprocess.Popen("rpm -qa --last|head -1|awk '{print $3}'", shell=True,stdout=subprocess.PIPE).stdout.read()
    RPMMONTH = subprocess.Popen("rpm -qa --last|head -1|awk '{print $4}'", shell=True,stdout=subprocess.PIPE).stdout.read()
    RPMYEAR = subprocess.Popen("rpm -qa --last|head -1|awk '{print $5}'", shell=True,stdout=subprocess.PIPE).stdout.read()
    RPMDAY = int(RPMDAY.rstrip())
    RPMMONTH = RPMMONTH.rstrip()
    RPMYEAR = int(RPMYEAR.rstrip())
    GETMONTH = int(GetMonth[RPMMONTH])

    RPMDATE = datetime(RPMYEAR,GETMONTH,RPMDAY)
    DDIFF = NOW - RPMDATE
    DDATE = str(DDIFF)
    DATEDIFF = DDATE.split('day')[0]

    if DATEDIFF < '30':
        ReportInfo("Last patch updated before %s days" % DATEDIFF)
    elif DATEDIFF <= '60':
        ReportWarn("Last patch updated before %s days" % DATEDIFF)
    elif DATEDIFF >= '90':
        ReportError("Please update system to latest patch, its %s days since last patch" % DATEDIFF)
    else:
        ReportDebug("No info found on system patch update, please debug")


""" A function to check the logrotate is configured and enabled
"""

def CheckLogrotate():

    FILE = '/etc/logrotate.conf'
    if os.path.isfile(FILE):
        CHECK  = subprocess.Popen("egrep '^compress|^#compress' /etc/logrotate.conf",shell=True,stdout=subprocess.PIPE).stdout.read()
        CHECK = CHECK.rstrip()
        if CHECK == '#compress':
            ReportError("Logrotate is disabled")
        elif CHECK == 'compress':
            ReportInfo("Logrotate is enabled")
        else:
            ReportDebug("Please debug manually logrotate config")
    else:
        ReportError("Log rotate not condfigured %s No such file" % FILE)

""" A class and methods to check OSSEC configuration
"""

class Ossec:

    def CheckOssecCfg(self):
        FILE = '/var/ossec/etc/ossec.conf'
        cmd = "grep server-ip /var/ossec/etc/ossec.conf|cut -d'>' -f2|cut -d'<' -f1"
        server = '10.163.224.50'
        if os.path.exists(FILE):
            ossecserver = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
            ossecserver = ossecserver.strip()
            if ossecserver == server:
                ReportInfo("OSSEC CHECK: The ossec server %s is valid"% ossecserver)
            else:
                ReportError("OSSEC CHECK: The ossec server %s is not a valid server"% ossecserver)
        else:
            ReportError("OSSEC CHECK: ossec configuration file %s not found"% FILE)

    def CheckOssecService(self):
        FILE = '/etc/init.d/ossec-hids'
        if os.path.exists(FILE):
            output = subprocess.Popen("/etc/init.d/ossec-hids status", shell=True, stdout=subprocess.PIPE).stdout.read()
            output = output.strip()
            output = output.split('\n')
            match = 'not'
            for line in output:
                if match:
                    ReportInfo("OSSEC CHECK: %s"% line)
                else:
                    ReportError("OSSEC CHECK: The service %s"% line)
        else:
            ReportError("OSSEC CHECK: The config file %s not found"% FILE)


""" A function to check the syslog or rsyslog is configured and service enabled
"""

def CheckSyslog():

    if osvers == '5':
        FILE = '/etc/syslog.conf'
        if os.path.isfile(FILE):
            CHECK = subprocess.Popen("service syslog status",shell=True,stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()

            if 'running' in CHECK:
                ReportInfo("Syslog service up and running")
            elif 'stopped' in CHECK:
                ReportError("Syslog service is stopped")
            else:
                ReportDebug("No Info found for syslog please debug")
        else:
            ReportError("%s: No such file" % FILE)
    elif osvers == '6':
        FILE = '/etc/rsyslog.conf'
        if os.path.isfile(FILE):
            CHECK = subprocess.Popen("service rsyslog status", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()

            if 'running' in CHECK:
                ReportInfo("rsyslog service up and running")
            elif 'stopped' in CHECK:
                ReportError("rsyslog service is stopped")
            else:
                ReportDebug("No Info found for rsyslog please debug")
        else:
            ReportError("%s: No such file" % FILE)
    elif osvers == '7':
        FILE = '/etc/rsyslog.conf'
        if os.path.isfile(FILE):
            CHECK = subprocess.Popen("systemctl is-active rsyslog.service", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()

            if 'inactive' in CHECK:
                ReportError("rsyslog service is stopped")
            elif 'active' in CHECK:
                ReportInfo("rsyslog service up and running")
            elif 'unknown' in CHECK:
                ReportError("rsyslogd service is not demonized")
            else:
                ReportDebug("No Info found for rsyslog service please debug")
        else:
            ReportError("%s: No such file!" % FILE)
    else:
        ReportError("OS version %s not match" % osvers)


""" A class and its methods to check the NTP configuration and service
"""

class CheckNtpCfg:

    def CheckNtpService(self):

        if osvers == '5' or osvers == '6':
            FILE = '/etc/init.d/ntpd'
            if os.path.isfile(FILE):
                CHECK = subprocess.Popen("service ntpd status", shell=True, stdout=subprocess.PIPE).stdout.read()
                CHECK = CHECK.rstrip()

                if 'running' in CHECK:
                    ReportInfo("ntpd service up and running")
                elif 'stopped' in CHECK:
                    ReportError("ntpd service is stopped")
                else:
                    ReportDebug("No Info found for ntpd service, please debug")
            else:
                ReportError("NTPD is not runnig %s No such file" % FILE)
        elif osvers == '7':
            CHECK = subprocess.Popen("systemctl is-active ntpd.service", shell=True, stdout=subprocess.PIPE).stdout.read()
            CHECK = CHECK.rstrip()

            if 'inactive' in CHECK:
                ReportError("ntpd.service service is stopped")
            elif 'active' in CHECK:
                ReportInfo("ntpd.service service up and running")
            elif 'unknown' in CHECK:
                ReportError("NTPD service is not deamonized")
            else:
                ReportDebug("No Info found for ntpd service, please debug")
        else:
            ReportError("OS version %s does not match" % osvers)

    def CheckDC(self):

        if len(sys.argv) < 2:
            Help()
        else:
            DC = sys.argv[2]
            return DC

    def GetTZ(self):

        C = CheckNtpCfg()
        DC = C.CheckDC()
        TZ = DCTZ[DC]
        return TZ

    def CheckNtpConfig(self):

        NTPSER = ['198.51.100.1', '198.51.100.2']
        CHKTZ = subprocess.Popen("date|awk '{print $5}'", shell=True, stdout=subprocess.PIPE).stdout.read()
        CHKTZ = CHKTZ.rstrip()
        GETNTPSER = subprocess.Popen("grep ^server /etc/ntp.conf |awk '{print $2}'|grep -v local", shell=True,stdout=subprocess.PIPE).stdout.read()
        GETNTPSER = GETNTPSER.rstrip()
        NSERVER = [item for item in GETNTPSER.split('\n')]
        NEWNSERVER = ' '.join(NSERVER)

        for lis in NEWNSERVER:
            NSERVER.append(lis)
            NSERVER = NSERVER[:2]

        C = CheckNtpCfg()
        GETDC = C.CheckDC()
        GETTZ = C.GetTZ()

        if GETDC in DCTZ.keys():
           ReportInfo("The DC info provided is valid")
        else:
            ReportError("DC name is not valid, please pass valid DC ID")
            Help()

        if CHKTZ in GETTZ:
            ReportInfo("Time zone is valid on server")
        else:
            ReportError("Time zone is invalid on server")

        if NSERVER[0] == NTPSER[0] and NSERVER[1] == NTPSER[1]:
            ReportInfo("NTP servers are configured properly")
        else:
            ReportError("NTP servers are not correct")

""" A class and methods to check Nimsoft configuration
"""

class NimsoftCfg:
    def CheckProbes(self):
        cmd = "ps -ef|grep nimbus|egrep -v 'grep|nimsoft'|awk '{print $8}'|cut -d'(' -f2|cut -d')' -f1"
        C = GetApps()
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = p.communicate()[0]
        output = output.strip()
        output = output.split()

        app = C.CheckApps()
        if app == "DB":
            ReportInfo("The running probes %s"% output)
            probes = ['net_connect', 'processes', 'dirscan', 'cdm', 'hdb', 'logmon', 'controller', 'spooler', 'mysql']
            missing_probes = list(set(probes).difference(output))
            if missing_probes is not None:
                ReportError("NIMBUS CHECK: The %s probes are missing on server"% missing_probes)
        elif app == "XOPS":
            ReportInfo("The running probes %s"% output)
            probes = ['net_connect', 'processes', 'dirscan', 'cdm', 'hdb', 'logmon', 'controller', 'spooler', 'url_response']
            missing_probes = list(set(probes).difference(output))
            if missing_probes is not None:
                ReportError("NIMBUS CHECK: The %s probes are missing on server"% missing_probes)
        else:
            ReportError("The server is not DB nor XOPS")

    def CheckHubInfo(self):
        FILE = '/opt/nimsoft/robot/robot.cfg'
        if os.path.exists(FILE):
            primhubname = subprocess.Popen("grep -w hub /opt/nimsoft/robot/robot.cfg|cut -d'=' -f2", shell=True,
                                       stdout=subprocess.PIPE).stdout.read()
            primhubname = primhubname.strip()

            sechubname = subprocess.Popen("grep -w secondary_hub /opt/nimsoft/robot/robot.cfg|cut -d'=' -f2", shell=True,
                                       stdout=subprocess.PIPE).stdout.read()
            sechubname = sechubname.strip()

            primhubip = subprocess.Popen("grep -w hubip /opt/nimsoft/robot/robot.cfg|cut -d'=' -f2", shell=True,
                                     stdout=subprocess.PIPE).stdout.read()
            primhubip = primhubip.strip()

            sechubip = subprocess.Popen("grep -w secondary_hubip /opt/nimsoft/robot/robot.cfg|cut -d'=' -f2", shell=True,
                                         stdout=subprocess.PIPE).stdout.read()
            sechubip = sechubip.strip()

            if not primhubname:
                ReportWarn("NIMBUS CHECK: The primary hub name is None")
            else:
                ReportInfo("NIMBUS CHECK: The primary hub name is %s" % (primhubname))
            if not primhubip:
                ReportWarn("NIMBUS CHECK: The primary hub IP is None")
            else:
                ReportInfo("NIMBUS CHECK: The primary hub IP is %s" % (primhubip))

            if not sechubname:
                ReportWarn("NIMBUS CHECK: The secondary hub name is None")
            else:
                ReportInfo("NIMBUS CHECK: The secondary hub name is %s" % (sechubname))
            if not sechubip:
                ReportWarn("NIMBUS CHECK: The secondary hub IP is None")
            else:
                ReportInfo("NIMBUS CHECK: The secondary hub name is %s" % (sechubip))
        else:
            ReportError("NIMBUS CHECK: nimsoft configuration is invalid, no robot.cfg file found")


""" A function to check the httpd service
"""

def CheckHttpService():
    C = GetApps()
    APP = C.CheckApps()

    if APP != "DB":
        if osvers == '5' or osvers == '6':
            FILE = '/etc/init.d/httpd'
            if os.path.isfile(FILE):
                SERVICE = subprocess.Popen("service httpd status", shell=True, stdout=subprocess.PIPE).stdout.read()
                SERVICE = SERVICE.rstrip()

                if 'running' in SERVICE:
                    ReportInfo("httpd service up and running")
                elif 'stopped' in SERVICE:
                    ReportWarn("httpd service is not running")
                else:
                    ReportDebug("No Info found for httpd service, please debug")
            else:
                ReportError("HTTPD is not running %s No such file" % FILE)
        elif osvers == '7':
            SERVICE = subprocess.Popen("systemctl is-active httpd.service", shell=True,stdout=subprocess.PIPE).stdout.read()
            SERVICE = SERVICE.rstrip()

            if 'inactive' in SERVICE:
                ReportError("httpd.service service is stopped")
            elif 'active' in SERVICE:
                ReportInfo("httpd.service service up and running")
            elif 'unknown' in SERVICE:
                ReportError("HTTPD service is not deamonized")
            else:
                ReportDebug("No Info found for httpd service, please debug")
    else:
        ReportInfo("This is DB server, no HTTPD service required")

def CheckBackupCfg():
    C = GetApps()
    GETAPP = C.CheckApps()

    output = subprocess.Popen("iptables -L|egrep -w 'tina|tina-msg'", shell=True, stdout=subprocess.PIPE).stdout.read()
    output = output.strip()

    if 'tina|tina-msg' in output:
        ReportInfo("Tina backup agent iptable rules are set")
    else:
        ReportError("Tina backup agent iptable rules are not set")

    if os.path.isfile("/etc/init.d/tina.tina"):
        service = subprocess.Popen("/etc/init.d/tina.tina status", shell=True, stdout=subprocess.PIPE).stdout.read()
        service = service.strip()
        if 'tina_daemon is running' in service:
            ReportInfo("Tina backup agent service is running")
        else:
            ReportError("Tina backup agent service is not running")
    else:
        ReportError("BACKUP: The tina deamon /etc/init.d/tina.tina not found")

    if GETAPP == "DB":
        service = subprocess.Popen("/etc/init.d/mysql status", shell=True, stdout=subprocess.PIPE).stdout.read()
        service = service.strip()
        cmd = "clustat |grep -w mysqldb|grep service|awk '{print $2}'"
        clusnode = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        clusnode = clusnode.strip()

        ret_mydata = subprocess.call(["ls", "/mysql/data"], stdout=open(os.devnull, 'w'),stderr=open(os.devnull, 'w'))
        if ret_mydata == 0:
            ReportInfo("The /mysql/data is configured")
        else:
            ReportError("The /mysql/data is not configured")
        ret_mymisc = subprocess.call(["ls", "/mysql/misc"], stdout=open(os.devnull, 'w'),stderr=open(os.devnull, 'w'))
        if ret_mymisc == 0:
            ReportInfo("The /mysql/misc is configured")
        else:
            ReportError("The /mysql/misc is not configured")

        if "MySQL running" in service:
            ret_backup = subprocess.call(["ls", "/mysql/misc/backups"], stdout=open(os.devnull, 'w'),stderr=open(os.devnull, 'w'))
            if ret_backup == 0:
                ReportInfo("MySQL BACKUP: The /mysql/misc/backups is configured")
            else:
                ReportError("MySQL BACKUP: The /mysql/misc/backups is not configured")
        else:
            ReportWarn("MySQL BACKUP: cluster is running on node %s, once fail over /mysql/misc/backups is created"% clusnode)

    elif GETAPP == "XOPS":
        ReportInfo("This is XOPS server no backup info provided")
    else:
        ReportDebug("This is server is not DB nor XOPS, please debug")

def LumensionService():

    if os.path.isfile("/etc/init.d/patchagent"):
        cmd = "/etc/init.d/patchagent status"
        service = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        service = service.strip()

        if "Running" in service:
            ReportInfo("Lumension Service is running")
        elif "Stopped" in service:
            ReportError("Lumension service is stopped")
        else:
            ReportError("Lumension client is not installed on the server")
    else:
        ReportError("Lumension client is not installed on the server")

def CactiInfoXops():
    IP = socket.gethostbyname(socket.gethostname())
    C = GetApps()
    APP = " "
    GETAPP = C.CheckApps()
    if GETAPP == 'XOPS':
        URL = 'http://%s:81/cacti' % IP
        ret = urllib2.urlopen('%s' % URL)
        if ret.code == 200:
            ReportInfo("CACTI: The cacti web page is accessible")
        else:
            ReportError("CACTI: The cacti web page is not accessible, received %d error code"% ret.code)

        URL = 'http://%s' % IP
        ret = urllib2.urlopen("%s"% URL).code
        if ret == 200:
            ReportInfo("XOPS: The xops web page is accessible")
        else:
            ReportError("XOPS: The xops web page is not accessible, received %d error code"% ret)

        cmd = "crontab -u cactiuser -l|egrep 'cacti/poller.php|rsyncrrds.sh'"
        service = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
        service = service.strip()

        if "cacti/poller.php" and "rsyncrrds.sh" in service:
            ReportInfo("CACTI: The crontab entries are valid")
        else:
            ReportError("CACTI: crontab entries are not found")
    else:
        APP = 'DB'

""" A main execution or the place where interpreter starts
"""

if __name__ == '__main__':

    Help()
    GeneralInfo()
    C = header()
    C.PrintHeader(" System-QA-Checks ", "         Script validating the system checks, please wait ...", 10)
    C = GetApps()
    C.PrintApp()
    C.CheckApps()
    CheckSELinux()
    CheckPing(host)
    CheckBond = CheckNetBondCfg()
    CheckBond.BondMasterFile()
    CheckBond.BondSlaves()
    CheckPatchUpdate()
    CheckLogrotate()
    C = Ossec()
    C.CheckOssecService()
    C.CheckOssecCfg()
    C = NimsoftCfg()
    C.CheckProbes()
    C.CheckHubInfo()
    CheckBackupCfg()
    CheckSyslog()
    CheckPort443()
    CheckChefRuns()
    CheckNtp = CheckNtpCfg()
    CheckNtp.CheckNtpService()
    CheckNtp.CheckNtpConfig()
    CheckHttpService()
    LumensionService()
    CactiInfoXops()
