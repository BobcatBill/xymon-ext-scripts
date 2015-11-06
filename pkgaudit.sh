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
#[pkg]
#        ENVFILE $XYMONCLIENTHOME/etc/xymonclient.cfg
#        CMD $XYMONCLIENTHOME/ext/pkgaudit.sh
#        LOGFILE $XYMONCLIENTLOGS/pkgaudit.log
#        INTERVAL 5m
#
# Now restart the xymon client to start using it.

# These can be overridden in xymonclient.cfg
: ${PKGAUDIT_COLOR="yellow"};		# Set color when results are found
: ${PKGAUDIT_JAILS="NO"};		# Audit jails if they don't run their own xymon-client
					# This needs to be capitalized "YES" to enable
: ${PKGAUDIT_JAILGREP="poudriere"};	# Argument to egrep to remove jails with name patterns.

# Xymon doesn't have /usr/local in PATH
PATH=${PATH}:/usr/local/bin:/usr/local/sbin

# Don't edit below unless you know what you're doing
COLUMN=pkgaudit
COLOR=green
PKGAUDIT_FLAGS="-r"
TMPFILE="$(mktemp -t xymon-client-pkgaudit)"
VULNXML="-f /var/db/pkg/vuln.xml"

if [ $? -ne 0 ]; then
	echo "$0: Can't create temp file, exiting..."
	exit 1
fi

# Build the pkg-audit message header for main host
echo "$(hostname) pkg audit status" >> ${TMPFILE}
echo "" >> ${TMPFILE}

# Run pkg audit and collect output for main host
pkg-static audit ${PKGAUDIT_FLAGS} ${VULNXML} >> ${TMPFILE} || export NONGREEN=1

# Check if we should run on jails too. Grep removes poudriere jails.
if [ ${PKGAUDIT_JAILS} = "YES" ]; then
	for i in $(jls | sed '1d' | egrep -v "${PKGAUDIT_JAILGREP}" | awk '{print $1}'); do
		JAILROOT=$(jls -j ${i} -h path | sed '1d')
		{ echo "" ;
		echo "##############################" ;
		echo "" ;
		echo "jail $(jls -j ${i} -h name | sed '/name/d') pkg audit status" ;
		echo "" ;
		pkg-static -o PKG_DBDIR=${JAILROOT}/var/db/pkg audit ${PKGAUDIT_FLAGS} ${VULNXML} ; } >> ${TMPFILE} || export NONGREEN=1
	done
fi

# Ingest all the pkg audit messages.
MSG=$(cat ${TMPFILE})

# NONGREEN was detected.
[ ${NONGREEN} ] && COLOR=${PKGAUDIT_COLOR}

# Set STATUS message for top of output
case "${COLOR}" in
	green)
		STATUS="&${COLOR} pkgaudit is OK"
		;;
	yellow)
		STATUS="&${COLOR} pkgaudit is WARNING"
		;;
	red)
		STATUS="&${COLOR} pkgaudit is CRITICAL"
		;;
esac

# Report results to Xymon
${XYMON} ${XYMSRV} "status ${MACHINE}.${COLUMN} ${COLOR} $(date)

${STATUS}

${MSG}
"

rm -f ${TMPFILE}

exit 0
