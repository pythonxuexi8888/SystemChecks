import pexpect
import os
import paramiko
import socket
import getpass


COMMAND_PROMPT = '[##] '
COMMAND_PROMPT2 = '[#:]'
TERMINAL_PROMPT = '(?i)terminal type\?'
TERMINAL_TYPE = 'vt100'
SSH_NEWKEY = '(?i)are you sure you want to continue connecting'
localpath = '/home/sashok/check_last_modified.sh'
remotepath = '/tmp/check_last_modified.sh'


nodes = []
host = ''

def UserLogin():
    user = raw_input("Username [%s]: " % getpass.getuser())
    if not user:
        user = getpass.getuser()
    pprompt = lambda: (getpass.getpass(),getpass.getpass('Retype your password:'))
    pass1,pass2 = pprompt()
    while pass1 != pass2:
         print('Passwords do not match. Try again')
         pass1,pass2 = pprompt()
    return user, pass1

class MyException(Exception):
    pass

def clearchild(child):
    child.before = ''
    child.after = ''
    child.buffer = ''
    return child

def sftp(host):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_host_keys(os.path.expanduser(os.path.join("~",".ssh","known_hosts")))
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host,username=cred[0],password=cred[1],timeout=60)
        sftp = ssh.open_sftp()
        sftp.put(localpath,remotepath)
        sftp.close()
        ssh.close()
    except Exception, e:
        return "Host-Error"
def platform(child):
    try:
        clearchild(child)
        child.sendline('sh /tmp/check_last_modified.sh')
        child.expect(COMMAND_PROMPT2)
        child.sendline(cred[1])
        #child.expect(COMMAND_PROMPT2)
        #print child.before
    except Exception, e:
        raise e

def sudo(child):
    try:
        clearchild(child)
        child.sendline('sudo su -')
        ret = child.expect([pexpect.TIMEOUT, '(?i)password'])
        if ret == 0:
            raise MyException('Sudo Timed out')
        elif ret == 1:
            child.sendline(cred[1])
            i = child.expect([COMMAND_PROMPT, TERMINAL_PROMPT])
            if i == 1:
                child.sendline (TERMINAL_TYPE)
                child.expect (COMMAND_PROMPT)
        return child
    except Exception, e:
        raise e

def login(child):
    CHECK='(publickey,gssapi-keyex,gssapi-with-mic,password).'
    try:
        clearchild(child)
        child.sendline(cred[0])
        i = child.expect([pexpect.TIMEOUT, COMMAND_PROMPT,'(?i)assword',CHECK])
        if i == 0:
            raise MyException('Timed out')
        elif i == 1:
             child.sendline (TERMINAL_TYPE)
             child.expect (COMMAND_PROMPT)
        elif i == 2:
            #child = login(child)
            #child = sudo(child)
            child.sendline (cred[1])
            child.expect (COMMAND_PROMPT)
            #child = sudo(child)
            #child.expect (COMMAND_PROMPT2)
            #return child
        elif i == 3:
            return False
        return child
    except Exception, e:
        return False

def connect(host):
    ssh_newkey = 'Are you sure you want to continue connecting'
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=no -l %s %s' % (cred[0], host), timeout=40)
    try:
        ret = child.expect([pexpect.TIMEOUT,SSH_NEWKEY, '(?i)password', '(?i)service name not known','(?i)Connection reset by peer'])
        if ret == 0:
            raise MyException('Timed out')
        elif ret == 1:
            child.sendline('yes')
            child.expect ('(?i)password')
            #child = sftp(child)
            child = login(child)
        elif ret == 2:
            #child = sftp(child)
            child = login(child)
            return child
        elif ret == 3:
            raise MyException("Error: Unable to resolve %s" % host)
            return child
        elif ret == 4:
            raise MyException("Error: Connections reset SSH %s" % host)
        else:
            raise MyException(child.before)
    except Exception, e:
        raise MyException ("Error %s" %host)

def controller(host):
    try:
        child = connect(host)
        p1 = platform(child)
        RESULT=[]
        Temp = child.before
        Temp = Temp.strip()
        Temp = Temp.split('\r\n')
        RESULT.append(Temp)
        RESULT=RESULT[0][1:(len(RESULT[0])-1)]

        if len(RESULT) == 1:
            print ("%s"%(RESULT[0]))
        elif len(RESULT) == 2:
            print ("%s"%(RESULT[1]))
        else:
            print ("%s"%(RESULT))
    except Exception, e:
      print ("%s" % (e))

if __name__ == '__main__':
    cred=UserLogin()
    with open('/tmp/host', 'r') as f:
        for l in f:
            n = l.strip()
            nodes.append(n)
    f.close()
    for n in nodes:
        sftp(n)
        controller(n)
