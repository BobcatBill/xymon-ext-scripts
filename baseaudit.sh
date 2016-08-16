#!/bin/sh
#-
# Copyright (c) 2016 Mark Felder
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
# the /usr/local/www/xymon/client/etc/localclient.cfg file:
#
#[baseaudit]
#        ENVFILE $XYMONCLIENTHOME/etc/xymonclient.cfg
#        CMD $XYMONCLIENTHOME/ext/baseaudit.sh
#        LOGFILE $XYMONCLIENTLOGS/baseaudit.log
#        INTERVAL 5m
#
# Now restart the xymon client to start using it.

# These can be overridden in xymonclient.cfg
: ${BASEAUDIT_COLOR="yellow"}         # Set color when results are found
: ${BASEAUDIT_JAILS="NO"}             # Audit jails if they don't run their own xymon-client
                                      # This needs to be capitalized "YES" to enable
: ${BASEAUDIT_JAILGREP="poudriere"}   # Argument to egrep to remove jails with name patterns.
: ${BASEAUDIT_FORCEFETCH="NO"}        # Attempt to always fetch vuln.xml -- every 5 mins!
                                      # This needs to be capitalized "YES" to enable

# Xymon doesn't have /usr/local in PATH
PATH=${PATH}:/usr/local/bin:/usr/local/sbin

# Don't edit below unless you know what you're doing
COLUMN=baseaudit
COLOR=green
BASEAUDIT_FLAGS=""
TMPFILE="$(mktemp -t xymon-client-baseaudit)"
VULNXML="-f /var/db/pkg/vuln.xml"

if [ $? -ne 0 ]; then
    echo "$0: Can't create temp file, exiting..."
    exit 1
fi

# Build the pkg-audit message header for main host
echo "$(hostname) base audit status" >> ${TMPFILE}
echo "" >> ${TMPFILE}

# If BASEAUDIT_FORCEFETCH is enabled, pass -F flag and set VULNXML to a path where Xymon can write
[ ${BASEAUDIT_FORCEFETCH} = "YES" ] && BASEAUDIT_FLAGS="${BASEAUDIT_FLAGS} -F" && VULNXML="-f /usr/local/www/xymon/client/tmp/vuln.xml"

if [ -e /bin/freebsd-version ] ; then
    export KERNELVER="$(uname -r)"
    export BASEVER="$(freebsd-version -u)"
else
    export NOBASEVER=YES # No freebsd-update, can't reliably identify base version
    export KERNELVER="$(uname -r)"
fi

# Check to make sure we're working with a RELEASE for the kernel
case "${KERNELVER}" in
    *PRERELEASE*)
      # Not a RELEASE
      export NOKERNELVER=YES
      ;;
    *RELEASE*)
      # It's a RELEASE, let's fixup the syntax
      export KERNELVER="$(echo ${KERNELVER} | sed 's,^,FreeBSD-kernel-,;s,-RELEASE-p,_,;s,-RELEASE$,,')"
      ;;
    *)
      # It's probably an ALPHA, BETA, or RC. It's not a RELEASE!
      export NOKERNELVER=YES
      ;;
esac

# Check to make sure we're working with a RELEASE for the base
case "${BASEVER}" in
    *PRERELEASE*)
      # Not a RELEASE
      export NOBASEVER=YES
      ;;
    *RELEASE*)
      # It's a RELEASE, let's fixup the syntax
      export BASEVER="$(echo ${BASEVER} | sed 's,^,FreeBSD-,;s,-RELEASE-p,_,;s,-RELEASE$,,')"
      ;;
    *)
      # It's probably an ALPHA, BETA, or RC. It's not a RELEASE!
      export NOBASEVER=YES
      ;;
esac

# Run pkg audit and collect output for main host
[ -z ${NOKERNELVER} ] && pkg-static audit ${BASEAUDIT_FLAGS} ${VULNXML} ${KERNELVER} >> ${TMPFILE} || export NONGREEN=1
printf "\n" >> ${TMPFILE}
[ -z ${NOBASEVER} ] && pkg-static audit ${BASEAUDIT_FLAGS} ${VULNXML} ${BASEVER} >> ${TMPFILE} || export NONGREEN=1

# Nothing to do on this server, exit
[ ${NOKERNELVER} ] && [ ${NOBASEVER} ] && [ ${BASEAUDIT_JAILS} = "NO" ] && exit 0

# Check if we should run on jails too. Grep removes poudriere jails.
if [ ${BASEAUDIT_JAILS} = "YES" ]; then
    for i in $(jls -N | sed '1d' | sort | egrep -v "${BASEAUDIT_JAILGREP}" | awk '{print $1}'); do
        JAILROOT=$(jls -j ${i} -h path | sed '1d')
        if [ -e ${JAILROOT}/bin/freebsd-version ]; then
          BASEVER=$(${JAILROOT}/bin/freebsd-version -u)
          # Check to make sure we're working with a RELEASE for the base
          case "${BASEVER}" in
            *PRERELEASE*)
              # Not a RELEASE, move to next jail
              continue 
              ;;
            *RELEASE*)
              # It's a RELEASE, let's fixup the syntax
              export BASEVER="$(echo ${BASEVER} | sed 's,^,FreeBSD-,;s,-RELEASE-p,_,;s,-RELEASE$,,')"
              ;;
            *)
              # It's probably an ALPHA, BETA, or RC. It's not a RELEASE! Move to next jail.
              continue
              ;;
          esac
        else
          continue
        fi
        { echo "" ;
        echo "##############################" ;
        echo "" ;
        echo "jail $(jls -j ${i} -h name | sed '/name/d') ${BASEVER} status" ;
        echo "" ;
        pkg-static -o PKG_DBDIR=${JAILROOT}/var/db/pkg audit ${BASEAUDIT_FLAGS} ${VULNXML} ${BASEVER} ; } >> ${TMPFILE} || export NONGREEN=1
    done
fi

# Ingest all the pkg audit messages.
MSG=$(cat ${TMPFILE})

# NONGREEN was detected.
[ ${NONGREEN} ] && COLOR=${BASEAUDIT_COLOR}

# Set STATUS message for top of output
case "${COLOR}" in
    green)
        STATUS="&${COLOR} baseaudit is OK"
        ;;
    yellow)
        STATUS="&${COLOR} baseaudit is WARNING"
        ;;
    red)
        STATUS="&${COLOR} baseaudit is CRITICAL"
        ;;
esac

# Report results to Xymon
${XYMON} ${XYMSRV} "status ${MACHINE}.${COLUMN} ${COLOR} $(date)

${STATUS}

${MSG}
"

rm ${TMPFILE}

exit 0
