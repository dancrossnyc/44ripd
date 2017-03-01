#!/bin/sh
#
# PROVIDE: ampr_44ripd
# REQUIRE: routing
# KEYWORD: shutdown
#
. /etc/rc.subr

load_rc_config ampr_44ripd

: ${ampr_44ripd_enable:="NO"}

ampr_44ripd_prog=${ampr_44ripd_prog:="/usr/local/libexec/44ripd"}
PIDFILE=${ampr_44ripd_pidfile:="/var/run/44ripd.pid"}

case "${ampr_44ripd_enable}" in
  YES|Yes|yes)
    ampr_44ripd_enable=1
    ;;
  NO|No|no|*)
    ampr_44ripd_enable=0
    ;;
esac

case "$1" in
  "start")
    if [ ${ampr_44ripd_enable} == 0 ]; then
      exit 0
    fi
    echo "Starting 44ripd..."
    ${ampr_44ripd_prog} ${ampr_44ripd_options} ${ampr_44ripd_local_ip} ${ampr_44ripd_ampr_ip}
    echo $! > ${PIDFILE}
    echo "done"
  ;;

  "stop")
    echo "Stopping 44ripd..."
    if [ -f ${PIDFILE} ] ; then
      kill `cat ${PIDFILE}`
      rm ${PIDFILE}
      echo "done"
    else
      echo "not running?"
    fi
  ;;

  "restart")
    echo "Restarting 44ripd..."
    $0 stop
    sleep 2
    $0 start
  ;;

  *)
    echo "$0 [start|stop|restart]"
  ;;

esac
