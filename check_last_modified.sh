#!/bin/sh

SYSLOG='syslog.log'
VMKERNEL='vmkernel.log'
VMKWARNING='vmkwarning.log'
BASEDIR='/scratch/log'
HOSTNAME=$(hostname)
IPADD=$(hostname -i)
SysLog() {
        if [ $(find $BASEDIR -mtime -1 -type f -name "$SYSLOG") ];then
            STATUS="True"
        else
            STATUS="False"
        fi
echo $STATUS
}

VmKernelLog() {
        if [ $(find $BASEDIR -mtime -1 -type f -name "$VMKERNEL") ];then
            STATUS="True"
        else
            STATUS="False"
        fi
echo $STATUS
}

VmkWarningLog() {
        if [ $(find $BASEDIR -mtime -1 -type f -name "$VMKWARNING") ];then
            STATUS="True"
        else
            STATUS="False"
        fi
echo $STATUS
}

Main() {
        if [ -d "$BASEDIR" ];then
           if [ "$(SysLog)" == "True" ];then
              syslog='SYSLOG-BAD'
           else
              syslog='SYSLOG-GOOD'
           fi
           if [ "$(VmKernelLog)" == "True" ];then
              vmkernellog='VMKERNELLOG-BAD'
           else
              vmkernellog='VMKERNELLOG-GOOD'
           fi
           if [ "$(VmkWarningLog)" == "True" ];then
              vmkwarning='VMKWARNING-BAD'
           else
              vmkwarning='VMKWARNING-GOOD'
           fi
           echo "$IPADD,$HOSTNAME,$syslog,$vmkernellog,$vmkwarning"
        else
           echo "BASEDIR-NOT-FOUND"
        fi

#echo "$syslog,$vmkernellog,$vmkwarning"
}
Main
rm -rf /tmp/check_last_modified.sh >/dev/null 2>&1
