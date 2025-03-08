#!/bin/bash

MISCDIR=$(dirname "$0")
UFTRACE="${MISCDIR}/../uftrace --libmcount-path=${MISCDIR}/../libmcount"
UOPTS=
PROG="${MISCDIR}/bench"
DATA=bench.data

# setup cpufreq (on a cpu)
CPU=3

function msg() {
  if [ "${VERBOSE}" != "1" ]; then
    return
  fi

  echo $*
}

function help() {
  echo "Usage: bench.sh [OPTION]"
  echo "  OPTION  -c N      Use CPU N during the benchmark. (default: 3)"
  echo "          -p PROG   Use program PROG. (default: ./bench)"
  echo "          -u UOPT   Use uftrace option UOPT. Please quote it."
  echo "          -v        Show verbose messages."
  echo "          -h        Show this help and exit."

  exit 0
}

function set_cpufreq() {
  NEWGOV=$1
  CPUFREQ="/sys/devices/system/cpu/cpufreq/policy${CPU}/scaling_governor"

  if [ ! -e ${CPUFREQ} ]; then
    msg "Skip setting cpufreq since the file is not found: ${CPUFREQ}"
    return
  fi

  if [ "${ORIG_GOV}" == "" ]; then
    ORIG_GOV=$(cat ${CPUFREQ})
  fi

  CURGOV=$(cat ${CPUFREQ})
  msg "Changing cpufreq governor: ${CURGOV} ==> ${NEWGOV} : ${CPUFREQ}"
  sudo sh -c "echo ${NEWGOV} > ${CPUFREQ}"
}

# parse command line options
while getopts "c:p:u:vh" arg; do
  case $arg in
    c)
      CPU=$OPTARG
      ;;
    p)
      PROG=$OPTARG
      ;;
    u)
      UOPTS=$OPTARG
      ;;
    v)
      VERBOSE=1
      ;;
    h)
      help
      ;;
  esac
done
shift $((OPTIND - 1))

ARGS=$*
TARGET="${PROG} ${ARGS}"
TASKSET="taskset -c ${CPU}"

echo "# uftrace bench"

# this will set $ORIG_GOV
set_cpufreq "performance"
sleep 1

# do not use taskset (CPU affinity) when cpufreq is not available
if [ "${ORIG_GOV}" == "" ]; then
  TASKSET=
fi

msg "running uftrace record ${UOPTS} with ${TARGET}"
${TASKSET} ${UFTRACE} record -d ${DATA} ${UOPTS} ${TARGET}
${UFTRACE} report -d ${DATA} -F 'leaf' -F '^nested' --no-sched -f self-avg,self-min -s func

set_cpufreq "${ORIG_GOV}"

rm -rf ${DATA}{,.old}
