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
#[zfs]
#        ENVFILE $XYMONCLIENTHOME/etc/xymonclient.cfg
#        CMD $XYMONCLIENTHOME/ext/zfs.sh
#        LOGFILE $XYMONCLIENTLOGS/zfs.log
#        INTERVAL 5m
#
# Now restart the xymon client to start using it.

# Xymon doesn't have /usr/local in PATH
PATH=${PATH}:/usr/local/bin:/usr/local/sbin

COLUMN=zfs
COLOR=green

MSG=$(for i in $(zpool list -H -o name); do
        case $(zpool list -H -o health ${i}) in
                ONLINE)
			echo "&green ${i} is ONLINE"
			echo ""
			zpool status ${i}
                        ;;
		*)
			echo "&red ${i} is DEGRADED"
			echo ""
			zpool status ${i}
	esac
done)

if echo "${MSG}" | grep -q DEGRADED ; then
	export COLOR=red
fi

STATUS="$(hostname) ZFS status"

${XYMON} ${XYMSRV} "status ${MACHINE}.${COLUMN} ${COLOR} $(date)

${STATUS}

${MSG}
"
