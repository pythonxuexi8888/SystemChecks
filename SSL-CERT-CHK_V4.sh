##This shell script is a simple wrapper around the openssl binary. It uses
##s_client to get certificate information from remote hosts, or x509 for local
##certificate files. It can parse out some of the openssl output or just dump all
##of it as text.

#Usage: $(basename $0) [options]


AWK=$(type -P awk)
DATE=$(type -P date)
GREP=$(type -P grep)
OPENSSL=$(type -P openssl)
PRINTF=$(type -P printf)
SED=$(type -P sed)
MKTEMP=$(type -P mktemp)
LOGFILE='/var/log/ssl_certs.logs'

RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)

if [ -f /usr/bin/mailx ];then MAIL="/usr/bin/mailx";
elif [ -f /bin/mail ];then MAIL="/bin/mail";
elif [ -f /usr/bin/mail ];then MAIL="/usr/bin/mail";
elif [ -f /sbin/mail ];then MAIL="/sbin/mail";
elif [ -f /usr/sbin/mail ];then MAIL="/usr/sbin/mail";
elif [ -f /usr/sbin/sendmail ];then MAIL="/usr/sbin/sendmail";
else MAIL="cantfindit";
fi

WARNDAYS=3000
QUIET="FALSE"
ALARM="FALSE"
CERTTYPE="pem"


GetDate() {
        TIME=$($DATE +%T)
        TODAYDATE=$($DATE "+%F")
        echo "$($DATE -d $TODAYDATE '+%b %-d %-Y') $TIME"
}

Date2Julian() {

    if [ "${1}" != "" ] && [ "${2}" != ""  ] && [ "${3}" != "" ];then
      d2j_tmpmonth=$((12 * ${3} + ${1} - 3))
      d2j_tmpyear=$(( ${d2j_tmpmonth} / 12))
      echo $(( (734 * ${d2j_tmpmonth} + 15) / 24
               - 2 * ${d2j_tmpyear} + ${d2j_tmpyear}/4
               - ${d2j_tmpyear}/100 + ${d2j_tmpyear}/400 + $2 + 1721119 ))
    else
      echo 0
    fi
}

GetMonth()
{
    case ${1} in
        Jan) echo 1 ;;Feb) echo 2 ;;Mar) echo 3 ;;Apr) echo 4 ;;May) echo 5 ;;Jun) echo 6 ;;
        Jul) echo 7 ;;Aug) echo 8 ;;Sep) echo 9 ;;Oct) echo 10 ;;Nov) echo 11 ;;Dec) echo 12 ;;
          *) echo  0 ;;
    esac
}

DateDiff()
{
    if [ "${1}" != "" ] &&  [ "${2}" != "" ];then
        echo $((${2} - ${1}))
    else
        echo 0
    fi
}

Prints()
{
    if [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ];then
        MIN_DATE=$(echo $4 | ${AWK} '{ print $1, $2, $4 }')
        ${PRINTF} "%-14s %-40s %-8s %-11s %-4s %-30s\n" "$(GetDate)" "$1:$2" "$6" "$3" "$MIN_DATE" "$5" >>$LOGFILE
    elif [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ];then
        ${PRINTF} "%-14s %-40s %-35s %-32s %-17s\n" "$(GetDate)" "$1:$2" "$7" "$8" "$6" >>$LOGFILE
    elif [ "${QUIET}" != "TRUE" ];then
        MIN_DATE=$(echo $4 | ${AWK} '{ print $1, $2, $4 }')
        ${PRINTF} "%-14s %-40s %-12s %-12s %-4s %-30s\n" "$(GetDate)" "$1:$2" "$3" "$MIN_DATE" "$5"  >>$LOGFILE
    fi
}

Header()
{
  if [ "${NOHEADER}" != "TRUE" ];then
     if [ "${QUIET}" != "TRUE" ] && [ "${ISSUER}" = "TRUE" ];then
         ${PRINTF} "\n%-35s %-17s %-8s %-11s %-4s %-4s\n" "Host"    "Cert Issuer"    "Status"   "Expires" "Days left"  >>$LOGFILE
         echo "-----"$($DATE "+%d-%m-%Y")"------------------------------------------------------------------------"  >>$LOGFILE
     elif [ "${QUIET}" != "TRUE" ];then
         ${PRINTF} "\n%-47s %-12s %-12s %-4s %-4s\n" "Host" "Status" "Expires" "Days left"  >>$LOGFILE
         echo "-----"$($DATE "+%d-%m-%Y")"-------------------------------------------------------------------------" >>$LOGFILE
      fi
  fi
}

Help()
{
    echo "Help: $0 [ -e email address ] [ -x days ] [-q] [-a] [-b] [-h] [-i]"
    echo "       { [ -f cert_file ] }"
    echo ""
    echo "  -a                : Send a warning message through E-mail"
    echo "  -b                : Will not print header"
    echo "  -c cert file      : Print the expiration date for the PEM or PKCS12 formatted certificate in cert file"
    echo "  -e E-mail address : E-mail address to send expiration notices"
    echo "  -f cert file      : File with a list of FQDNs and ports"
    echo "  -h                : Print this screen"
    echo "  -i                : Print the issuer of the certificate"
    echo "  -p port           : Port to connect to (interactive mode)"
    echo "  -t type           : Specify the certificate type"
    echo "  -q                : Don't print anything on the console"
    echo "  -x days           : Certificate expiration interval (eg. if cert_date < days)"
    echo ""
}

CheckServerStatus() {

    if [ "${TLSSERVERNAME}" = "TRUE" ];then
         TLSFLAG="${TLSFLAG} -servername $1"
    fi

    echo "" | ${OPENSSL} s_client ${VER} -connect ${1}:${2} ${TLSFLAG} 2> ${ERROR_TMP} 1> ${CERT_TMP}

    if ${GREP} -i  "Connection refused" ${ERROR_TMP} > /dev/null;then
        Prints ${1} ${2} "Connection refused" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    elif ${GREP} -i "No route to host" ${ERROR_TMP} > /dev/null;then
        Prints ${1} ${2} "No route to host" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    elif ${GREP} -i "gethostbyname failure" ${ERROR_TMP} > /dev/null;then
        Prints ${1} ${2} "Cannot resolve domain" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    elif ${GREP} -i "Operation timed out" ${ERROR_TMP} > /dev/null;then
         ${1} ${2} "Operation timed out" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    elif ${GREP} -i "ssl handshake failure" ${ERROR_TMP} > /dev/null;then
        Prints ${1} ${2} "SSL handshake failed" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    elif ${GREP} -i "connect: Connection timed out" ${ERROR_TMP} > /dev/null;then
        Prints ${1} ${2} "Connection timed out" "Unknown" $($DATE "+%d-%m-%Y") >>$LOGFILE
        RETURN=3
    else
        CheckFileStatus ${CERT_TMP} $1 $2
    fi
}

CheckFileStatus()
{
  CERTFILE=${1}
  HOST=${2}
  PORT=${3}

  if [ ! -r ${CERTFILE} ] || [ ! -s ${CERTFILE} ];then
      echo "ERROR: The file named ${CERTFILE} is unreadable or doesn't exist for ${HOST}" $($DATE "+%d-%m-%Y") >>$LOGFILE
      echo "ERROR: Please check to make sure the certificate for ${HOST}:${PORT} is valid" >>$LOGFILE
      RETURN=1
      return
  fi

      CERTDATE=$(${OPENSSL} x509 -in ${CERTFILE} -enddate -noout -inform ${CERTTYPE}|${SED} 's/notAfter\=//')
      CERTISSUER=$(${OPENSSL} x509 -in ${CERTFILE} -issuer -noout -inform ${CERTTYPE}|${AWK} 'BEGIN {RS="/" } $0 ~ /^O=/ { print substr($0,3,17)}')
      COMMONNAME=$(${OPENSSL} x509 -in ${CERTFILE} -subject -noout -inform ${CERTTYPE}|${SED} -e 's/.*CN=//' | ${SED} -e 's/\/.*//')
      SERIAL=$(${OPENSSL} x509 -in ${CERTFILE} -serial -noout -inform ${CERTTYPE}|${SED} -e 's/serial=//')

  set -- ${CERTDATE}
  MONTH=$(GetMonth ${1})

  CERTJULIAN=$(Date2Julian ${MONTH#0} ${2#0} ${4})
  CERTDIFF=$(DateDiff ${NOWJULIAN} ${CERTJULIAN})

  if [ ${CERTDIFF} -le 0 ];then
      if [ "${ALARM}" = "TRUE" ];then
        #cat << 'EOF' >> mail.html
        ( echo "To: srinivas.ashok@itaas.dimensiondata.com,niraj.kumar@dimensiondata.com,sandeep.ch@itaas.dimensiondata.com"
          echo "Subject: SSL Certification Expired"
          echo "Content-Type: text/html; charset='us-ascii'"
          echo "<html>
        <body>
        <p>
        <font size="4" face="Courier" color="red">
        <b>CRITICAL: The SSL certificate for ${HOST} \"(CN: ${COMMONNAME})\" has expired!</b>
        <br>
        <font size="4" face="Courier" color="orchid">
        <b>Previous Certification Issuer: ${CERTISSUER}</b>
        <br>
        <b>Serial No of certificate: ${SERIAL}</b>
        <br>
        <font size="4" face="Courier" color="salmon">
        <b>Please initiate the SSL certificate reneval process soon...</b>
        <b>Please click on https://10.118.19.13/cgi-bin/ssl_cert.py for more info</b>
        <font size="4" face="Courier" color="salmon">
        </font>
        </p>
        </body>
        </html>"
        ) | /usr/sbin/sendmail -t
        Prints ${HOST} ${PORT} "CRITICAL: Expired" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}" >>${LOGFILE}
      RETURN=2
    fi
  elif [ ${CERTDIFF} -lt ${WARNDAYS} ];then
      if [ "${ALARM}" = "TRUE" ];then
        ( echo "To: srinivas.ashok@itaas.dimensiondata.com,niraj.kumar@dimensiondata.com,sandeep.ch@itaas.dimensiondata.com"
          echo "Subject: SSL Certification Expire update"
          echo "Content-Type: text/html; charset='us-ascii'"
          echo "<html>
        <body>
        <p>
        <font size="4" face="Courier" color="gold">
        <b>WARNING: The SSL certificate for ${HOST} \"(CN: ${COMMONNAME})\" expiring on "${CERTDATE}"</b>
        <br>
        <font size="4" face="Courier" color="orchid">
        <b>Current Certification Issuer: ${CERTISSUER}</b>
        <br>
        <b>Serial No of certificate: ${SERIAL}</b>
        <br>
        <font size="4" face="Courier" color="salmon">
        <b>Please make sure to reneval the SSL certificate before expiry.</b>
        <br>
        <b>Please click on https://10.118.19.13/cgi-bin/ssl_cert.py for more info</b>
        </font>
        </p>
        </body>
        </html>"
        ) | /usr/sbin/sendmail -t
      fi
      Prints ${HOST} ${PORT} "WARNING: Expiring on" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}" >>${LOGFILE}
      RETURN=1
  else
      Prints ${HOST} ${PORT} "Valid" "${CERTDATE}" "${CERTDIFF}" "${CERTISSUER}" "${COMMONNAME}" "${SERIAL}" >>$LOGFILE
      RETURN=0
  fi
}

#################################
### Main
#################################
while getopts abiv:e:f:c:hk:p:s:t:qx:V option
do
    case "${option}"
    in
        a) ALARM="TRUE";;
        b) NOHEADER="TRUE";;
        c) CERTFILE=${OPTARG};;
        e) ADMIN=${OPTARG};;
        f) SERVERFILE=$OPTARG;;
        h) Help;exit 1;;
        i) ISSUER="TRUE";;
        p) PORT=$OPTARG;;
        s) HOST=$OPTARG;;
        t) CERTTYPE=$OPTARG;;
        q) QUIET="TRUE";;
        x) WARNDAYS=$OPTARG;;
       \?) Help
           exit 1;;
    esac
done

if ${OPENSSL} s_client -h 2>&1 | grep '-servername' > /dev/null;then
    TLSSERVERNAME="TRUE"
else
    TLSSERVERNAME="FALSE"
fi

CERT_TMP=$($MKTEMP  /var/tmp/cert.XXXXXX)
ERROR_TMP=$($MKTEMP /var/tmp/error.XXXXXX)

MONTH=$(${DATE} "+%m")
DAY=$(${DATE} "+%d")
YEAR=$(${DATE} "+%Y")
NOWJULIAN=$(Date2Julian ${MONTH#0} ${DAY#0} ${YEAR})

if [ ! -z "${CERT_TMP}" ] && [ ! -z "${ERROR_TMP}" ];then
    touch ${CERT_TMP} ${ERROR_TMP}
else
    echo "ERROR: Problem creating temporary files" $($DATE "+%d-%m-%Y") >>$LOGFILE
    echo "FIX: Check that mktemp works on your system" $($DATE "+%d-%m-%Y") >>$LOGFILE
    exit 1
fi

if [ "${HOST}" != "" ] && [ "${PORT}" != "" ];then
    Header
    CheckServerStatus "${HOST}" "${PORT}"
elif [ -f "${SERVERFILE}" ];then
    Header
    egrep -v '(^#|^$)' ${SERVERFILE} |  while read HOST PORT
    do
        if [ "$PORT" = "FILE" ];then
            CheckFileStatus ${HOST} "FILE" "${HOST}"
        else
            CheckServerStatus "${HOST}" "${PORT}"
        fi
    done
elif [ "${CERTFILE}" != "" ];then
    Header
    CheckFileStatus ${CERTFILE} "FILE"  "${CERTFILE}"
else
    Help
    exit 1
fi

rm -f ${CERT_TMP} ${ERROR_TMP}
