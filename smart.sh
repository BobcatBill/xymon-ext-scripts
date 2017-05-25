#!/bin/sh
#-
# Copyright (c) 2015 Mark Felder
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

#
# Place this file in /usr/local/www/xymon/client/ext/
# Then, to activate simply append the following to
# the /usr/local/www/xymon/client/etc/clientlaunch.cfg file:
#
#[smart]
#        ENVFILE $XYMONCLIENTHOME/etc/xymonclient.cfg
#        CMD $XYMONCLIENTHOME/ext/smart.sh
#        LOGFILE $XYMONCLIENTLOGS/smart.log
#        INTERVAL 5m
#
# You may also need to add something like this to your sudoers file:
# 
# Cmnd_Alias SMARTCTL = /usr/local/sbin/smartctl
# xymon ALL=SMARTCTL, NOPASSWD: SMARTCTL
#
# Now restart the xymon client to start using it.

# Xymon doesn't have /usr/local in PATH
PATH=${PATH}:/usr/local/bin:/usr/local/sbin

COLUMN=smart

MSG=$(for i in $(sysctl -n kern.disks | tr ' ' '\n' | sort | egrep -v '^(cd|nvd)'); do
	OUTPUT=$(sudo smartctl -a /dev/${i});
	SERIAL=$(echo "${OUTPUT}" | awk '/Serial/ {print $3}')
        if [ "x${SERIAL}" == "x" ]; then SERIAL="null"; fi
	MODEL=$(echo "${OUTPUT}" | awk '/Device Model/ {print $3,$4}')
        if [ "x${MODEL}" == "x" ]; then MODEL="null"; fi
	REALLOCATED=$(echo "${OUTPUT}" | awk '/Reallocated_Sector/ {print $10}')
        if [ "x${REALLOCATED}" == "x" ]; then REALLOCATED=0; fi
	TEMP=$(echo "${OUTPUT}" | awk '/Temperature_Celsius/ {print $10}')
        if [ "x${TEMP}" == "x" ]; then TEMP=0; fi

	if [ "${REALLOCATED}" -gt 0 ] ; then
		HEALTH="FAILED"
	elif [ "${TEMP}" -gt 45 ] ; then
                HEALTH="FAILED"
	else
		HEALTH=$(echo "${OUTPUT}" | grep "overall-health")
	fi

        case "${HEALTH}" in
                *PASSED)
			echo "&green ${i} PASSED [ Serial: ${SERIAL} Model: ${MODEL} Reallocated: ${REALLOCATED} Temp: ${TEMP} ]"
                        ;;
                "")
			echo "&yellow ${i} PASSED [ Serial: ${SERIAL} Model: ${MODEL} Reallocated: ${REALLOCATED} Temp: ${TEMP} ]"
                        ;;
		*)
			echo "&red ${i} FAILED [ Serial: ${SERIAL} Model: ${MODEL} Reallocated: ${REALLOCATED} Temp: ${TEMP} ]"
			;;
	esac
done)

STATUS="$(hostname) SMART health status"

case "${MSG}" in
	*'&red'*)
		COLOR=red
		;;
	*'&yellow'*)
		COLOR=yellow
		;;
	*)
		COLOR=green
		;;
esac

${XYMON} ${XYMSRV} "status ${MACHINE}.${COLUMN} ${COLOR} $(date)

${STATUS}

${MSG}
"
