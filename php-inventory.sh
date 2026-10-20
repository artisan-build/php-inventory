#!/bin/sh
# php-inventory.sh -- read-only PHP inventory for one host.
#
# Prints a sectioned report to stdout and to /tmp/php-inventory-<hostname>.txt.
# Reads only: installs nothing, changes no config, writes nothing outside /tmp.
# Runs without root; anything that needs privilege is reported under SKIPPED
# rather than silently omitted.
#
# Written for the oldest hosts it is likely to meet -- Ubuntu 14.04 and Amazon
# Linux AMI 2015.03 -- so it is /bin/sh, assumes no jq, and avoids ERE interval
# syntax that mawk 1.3.3 does not implement.

FORMAT_VERSION=1
SCRIPT_VERSION=1

HOSTNAME_VAL=`hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown`
UID_VAL=`id -u 2>/dev/null || echo unknown`

# Pick a writable path under /tmp. If another user already ran the script the
# obvious name belongs to them and is not ours to overwrite, so fall back to a
# per-uid name rather than failing or -- worse -- printing their file as ours.
OUT=""
for cand in "/tmp/php-inventory-${HOSTNAME_VAL}.txt" \
            "/tmp/php-inventory-${HOSTNAME_VAL}-${UID_VAL}.txt" \
            "/tmp/php-inventory-${HOSTNAME_VAL}-$$.txt"; do
    if ( : > "$cand" ) 2>/dev/null; then OUT="$cand"; break; fi
done
if [ "$UID_VAL" = 0 ]; then IS_ROOT=yes; else IS_ROOT=no; fi

SKIPPED_FILE=/tmp/.php-inventory-skipped.$$
TMP_PS=/tmp/.php-inventory-ps.$$
: > "$SKIPPED_FILE"

cleanup() { rm -f "$SKIPPED_FILE" "$TMP_PS"; }
trap cleanup EXIT
trap 'cleanup; exit 1' HUP INT TERM

skip() { printf '%s\t%s\n' "$1" "$2" >> "$SKIPPED_FILE"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Redaction. The whole report passes through this one filter, so nothing that
# any section collects can reach stdout or the file with a credential in it.
#
#   scheme://user:pass@host  and  scheme://token@host  ->  scheme://REDACTED@host
#   token=... / password: ... / bearer ...             ->  REDACTED-SECRET
#
# Ubuntu Pro writes https://bearer:TOKEN@esm.ubuntu.com lines into
# sources.list.d, which is the case that made this non-optional.
# ---------------------------------------------------------------------------
redact() {
    awk '
    BEGIN {
        uri_re = "://[^ \t/@]*@"
        kv_re  = "([Tt][Oo][Kk][Ee][Nn]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Bb][Ee][Aa][Rr][Ee][Rr]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy])[ \t]*[:=][ \t\"'"'"']*[A-Za-z0-9/+=._-][A-Za-z0-9/+=._-]*"
    }
    {
        # Forward scan: each pass consumes the matched prefix, so an already
        # redacted "://REDACTED@" can never be rematched into a loop.
        line = $0
        out = ""
        while (match(line, uri_re)) {
            out = out substr(line, 1, RSTART + 2) "REDACTED@"
            line = substr(line, RSTART + RLENGTH)
        }
        out = out line
        gsub(kv_re, "REDACTED-SECRET", out)
        print out
    }'
}

# ---------------------------------------------------------------------------
report() {

echo "#### BEGIN PHP-INVENTORY"
echo "format_version: $FORMAT_VERSION"
echo "script_version: $SCRIPT_VERSION"
echo "generated_at: `date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date 2>/dev/null`"

echo ""
echo "#### SECTION HOST"
echo "hostname: $HOSTNAME_VAL"
echo "uname_m: `uname -m 2>/dev/null || echo unknown`"
echo "uname_r: `uname -r 2>/dev/null || echo unknown`"
echo "uid: $UID_VAL"
echo "is_root: $IS_ROOT"

echo ""
echo "#### SECTION OS"
if [ -r /etc/os-release ]; then
    echo "source: /etc/os-release"
    sed -e 's/^/osrelease: /' /etc/os-release 2>/dev/null
elif [ -r /etc/lsb-release ]; then
    echo "source: /etc/lsb-release"
    sed -e 's/^/osrelease: /' /etc/lsb-release 2>/dev/null
else
    echo "source: none"
fi
[ -r /etc/system-release ] && echo "system_release: `cat /etc/system-release 2>/dev/null`"
[ -r /etc/debian_version ] && echo "debian_version: `cat /etc/debian_version 2>/dev/null`"
have lsb_release && echo "lsb_codename: `lsb_release -cs 2>/dev/null`"

echo ""
echo "#### SECTION PHP_PACKAGES"
echo "# fields: manager<TAB>package<TAB>version<TAB>state"
if have dpkg-query; then
    for pat in 'php*' 'libapache2-mod-php*'; do
        dpkg-query -W -f='${Package} ${Version} ${Status}\n' "$pat" 2>/dev/null
    done | awk 'NF >= 2 {
        st = ""
        if ($0 ~ / install ok installed$/) st = "installed"
        else if ($0 ~ /deinstall/)         st = "config-files"
        # dpkg knows every php package name in the archive; only the ones
        # actually on the disk are worth reporting.
        if (st != "") print "dpkg\t" $1 "\t" $2 "\t" st
    }' | sort -u
elif have rpm; then
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'php*' 2>/dev/null |
        awk 'NF { print "rpm\t" $1 "\t" $2 "\tinstalled" }' | sort -u
else
    echo "# no dpkg-query and no rpm on this host"
    skip PHP_PACKAGES "neither dpkg-query nor rpm is present"
fi

echo ""
echo "#### SECTION PKG_ORIGIN"
echo "# where each php cli / fpm / mod_php package actually came from"
if have apt-cache && have dpkg-query; then
    PKGS=`for pat in 'php*' 'libapache2-mod-php*'; do
              dpkg-query -W -f='${Package} ${Status}\n' "$pat" 2>/dev/null
          done |
          grep ' install ok installed$' |
          awk '{print $1}' |
          grep -E '^(php5|php5-fpm|php5-cli|php[0-9]+\.[0-9]+-(fpm|cli)|php-fpm|php-cli|libapache2-mod-php.*)$' |
          sort -u`
    [ -n "$PKGS" ] || echo "# no php cli/fpm/mod_php packages installed"
    for p in $PKGS; do
        echo "package: $p"
        apt-cache policy "$p" 2>/dev/null |
            sed -n -e 's/^ *Installed: /  installed: /p' \
                   -e 's/^ *Candidate: /  candidate: /p' \
                   -e 's/^ *\*\*\* \(.*\)$/  origin_selected: \1/p' \
                   -e 's/^ *\([0-9][^ ]*\) \([0-9][0-9]*\)$/  version_entry: \1 \2/p' \
                   -e 's/^ *\([0-9][0-9]*\) \(.*\)$/  origin: \1 \2/p'
        echo "end_package: $p"
    done
elif have yum; then
    echo "# fields: yum<TAB>package<TAB>version<TAB>repo"
    yum list installed 'php*' 2>/dev/null |
        awk 'NF >= 3 && $1 ~ /^php/ { print "yum\t" $1 "\t" $2 "\t" $3 }'
elif have rpm; then
    echo "# rpm present but no yum: repository of origin is not recoverable"
    skip PKG_ORIGIN "rpm host without yum; package origin cannot be determined"
else
    echo "# no apt-cache, yum or rpm"
    skip PKG_ORIGIN "no package manager found"
fi

echo ""
echo "#### SECTION APT_SOURCES"
echo "# credentials in URIs are replaced with REDACTED before printing"
if [ -d /etc/apt ]; then
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -e "$f" ] || continue
        echo "file: $f"
        if [ -r "$f" ]; then
            grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -v '^[[:space:]]*$' | sed -e 's/^/  /'
        else
            echo "  (unreadable as this user)"
            skip APT_SOURCES "$f unreadable without root"
        fi
    done
    echo "dir_listing:"
    LS_D=`ls -1 /etc/apt/sources.list.d/ 2>/dev/null`
    if [ -n "$LS_D" ]; then echo "$LS_D" | sed -e 's/^/  /'; else echo "  (empty)"; fi
else
    echo "# /etc/apt does not exist"
fi

echo ""
echo "#### SECTION PRO_STATUS"
if have pro; then
    pro status 2>&1 | sed -e 's/^/  /'
elif have ua; then
    ua status 2>&1 | sed -e 's/^/  /'
else
    echo "  (ubuntu pro client not installed)"
fi

echo ""
echo "#### SECTION PHP_BINARIES"
echo "# every php binary on PATH and in the usual prefixes"
SEEN=""
CANDIDATES=`{
    for d in /usr/bin /usr/local/bin /usr/sbin /usr/local/sbin /opt/php*/bin /opt/*/php*/bin /usr/local/php*/bin; do
        [ -d "$d" ] || continue
        ls -1 "$d" 2>/dev/null | grep -E '^php([0-9]+(\.[0-9]+)?)?$' | sed -e "s#^#$d/#"
    done
    echo "$PATH" | tr ':' '\n' | while read -r d; do
        [ -n "$d" ] && [ -d "$d" ] || continue
        ls -1 "$d" 2>/dev/null | grep -E '^php([0-9]+(\.[0-9]+)?)?$' | sed -e "s#^#$d/#"
    done
} 2>/dev/null | sort -u`
[ -n "$CANDIDATES" ] || echo "# no php binary found"
for b in $CANDIDATES; do
    [ -x "$b" ] || continue
    REAL=`readlink -f "$b" 2>/dev/null || echo "$b"`
    case " $SEEN " in *" $REAL "*) continue ;; esac
    SEEN="$SEEN $REAL"
    echo "binary: $b"
    echo "  realpath: $REAL"
    VLINE=`"$b" -v 2>/dev/null | head -n 1`
    if [ -n "$VLINE" ]; then
        echo "  version: $VLINE"
    else
        echo "  version: (php -v produced no output)"
        skip PHP_BINARIES "$b did not respond to -v"
    fi
    "$b" -i 2>/dev/null > "$TMP_PS"
    CFG=`grep -m1 '^Configure Command' "$TMP_PS" 2>/dev/null`
    if [ -n "$CFG" ]; then echo "  $CFG"; else echo "  Configure Command => (not reported)"; fi
    INI=`grep -m1 '^Loaded Configuration File' "$TMP_PS" 2>/dev/null`
    [ -n "$INI" ] && echo "  $INI"
    : > "$TMP_PS"
    MODS=`"$b" -m 2>/dev/null | grep -v '^\[' | grep -v '^[[:space:]]*$' | tr '\n' ',' | sed -e 's/,$//'`
    echo "  modules: $MODS"
    echo "end_binary: $b"
done

echo ""
echo "#### SECTION FPM_PROCESSES"
echo "# fields: role<TAB>pid<TAB>user<TAB>exe<TAB>args"
ps -eo pid=,user=,args= 2>/dev/null > "$TMP_PS" || : > "$TMP_PS"
if [ ! -s "$TMP_PS" ]; then
    ps auxww 2>/dev/null | awk 'NR > 1 { u = $1; p = $2; $1=""; $2=""; $3=""; $4=""; $5=""; $6=""; $7=""; $8=""; $9=""; $10=""; sub(/^ +/, ""); print p " " u " " $0 }' > "$TMP_PS"
fi
FPM_FOUND=0
FPM_LINES=`grep -E 'php[0-9.]*-fpm|php-fpm|php5-fpm' "$TMP_PS" 2>/dev/null | grep -v 'php-inventory' | grep -v '[g]rep'`
if [ -n "$FPM_LINES" ]; then
    echo "$FPM_LINES" | while IFS= read -r l; do
        [ -n "$l" ] || continue
        pid=`echo "$l" | awk '{print $1}'`
        usr=`echo "$l" | awk '{print $2}'`
        args=`echo "$l" | awk '{ $1=""; $2=""; sub(/^ +/, ""); print }'`
        exe=`readlink /proc/$pid/exe 2>/dev/null`
        [ -n "$exe" ] || exe="(unreadable)"
        # php-fpm normally renames the master to "php-fpm: master process (...)",
        # but that depends on setproctitle, so a master can show up as the bare
        # binary path. Workers drop privileges; a root php-fpm that is not a
        # pool worker is a master. Calling it master when unsure is the safe
        # error: the summariser only flags "installed but not running".
        case "$args" in
            *"master process"*) role=master ;;
            *"pool "*)          role=worker ;;
            *)                  if [ "$usr" = root ]; then role=master; else role=other; fi ;;
        esac
        printf '%s\t%s\t%s\t%s\t%s\n' "$role" "$pid" "$usr" "$exe" "$args"
    done
    echo "$FPM_LINES" | grep -q 'master process' && FPM_FOUND=1
    echo "$FPM_LINES" | awk '$2 == "root"' | grep -qv 'pool ' && FPM_FOUND=1
fi
[ "$FPM_FOUND" = 1 ] || echo "# no php-fpm master process running"
[ "$IS_ROOT" = yes ] || skip FPM_PROCESSES "not root: /proc/<pid>/exe for other users' masters is unreadable, so exe may be blank"
: > "$TMP_PS"

echo ""
echo "#### SECTION FPM_POOLS"
echo "# fields: conffile<TAB>pool<TAB>listen"
POOLCONFS=""
for d in /etc/php/*/fpm/pool.d /etc/php5/fpm/pool.d /etc/php-fpm.d /etc/php-fpm-*.d /usr/local/etc/php-fpm.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*.conf; do
        [ -e "$f" ] && POOLCONFS="$POOLCONFS $f"
    done
done
[ -n "$POOLCONFS" ] || echo "# no fpm pool configuration directories found"
for f in $POOLCONFS; do
    if [ ! -r "$f" ]; then
        printf '%s\t%s\t%s\n' "$f" "(unreadable)" "(unreadable)"
        skip FPM_POOLS "$f unreadable without root"
        continue
    fi
    awk -v FN="$f" '
        /^[ \t]*\[/ { pool = $0; gsub(/[][ \t]/, "", pool) }
        /^[ \t]*listen[ \t]*=/ {
            v = $0; sub(/^[^=]*=[ \t]*/, "", v)
            print FN "\t" (pool == "" ? "(none)" : pool) "\t" v
        }
    ' "$f" 2>/dev/null
done

echo ""
echo "#### SECTION APACHE_MODPHP"
APA=""
for c in apache2ctl apachectl httpd; do
    have "$c" && { APA="$c"; break; }
done
if [ -z "$APA" ]; then
    echo "  (apache not installed)"
else
    echo "  binary: $APA"
    MODS=`$APA -M 2>/dev/null`
    if [ -z "$MODS" ]; then
        echo "  (module list unavailable -- apache2ctl -M normally needs root)"
        skip APACHE_MODPHP "$APA -M returned nothing; it normally requires root"
    else
        PHPMODS=`echo "$MODS" | grep -i php`
        if [ -n "$PHPMODS" ]; then
            echo "$PHPMODS" | sed -e 's/^[[:space:]]*/  mod: /'
        else
            echo "  mod: (no php module loaded)"
        fi
    fi
fi

echo ""
echo "#### SECTION LISTENING"
echo "# listening TCP sockets"
if have ss; then
    SOCKS=`ss -ltnp 2>/dev/null`
    [ -n "$SOCKS" ] || SOCKS=`ss -ltn 2>/dev/null`
    if [ -n "$SOCKS" ]; then echo "$SOCKS" | sed -e 's/^/  /'; else echo "  (ss produced no output)"; fi
    [ "$IS_ROOT" = yes ] || skip LISTENING "not root: ss cannot name the processes behind other users' sockets"
elif have netstat; then
    SOCKS=`netstat -ltnp 2>/dev/null`
    [ -n "$SOCKS" ] || SOCKS=`netstat -ltn 2>/dev/null`
    if [ -n "$SOCKS" ]; then echo "$SOCKS" | sed -e 's/^/  /'; else echo "  (netstat produced no output)"; fi
    [ "$IS_ROOT" = yes ] || skip LISTENING "not root: netstat cannot name the processes behind other users' sockets"
else
    echo "  (neither ss nor netstat is installed)"
    skip LISTENING "neither ss nor netstat is installed"
fi

echo ""
echo "#### SECTION DOCKER"
if have docker; then
    DPS=`docker ps --format '{{.Image}}	{{.Names}}	{{.Status}}' 2>/dev/null`
    [ -n "$DPS" ] || DPS=`docker ps 2>/dev/null`
    if [ -n "$DPS" ]; then
        echo "$DPS" | sed -e 's/^/  /'
    else
        echo "  (docker installed but docker ps returned nothing: no containers, or no permission)"
        skip DOCKER "docker ps returned nothing; it needs root or membership of the docker group"
    fi
else
    echo "  (docker not installed)"
fi

echo ""
echo "#### SECTION SKIPPED"
echo "# fields: section<TAB>reason"
if [ -s "$SKIPPED_FILE" ]; then
    sort -u "$SKIPPED_FILE"
else
    echo "# nothing skipped"
fi

echo ""
echo "#### END PHP-INVENTORY"
}

if [ -n "$OUT" ]; then
    report 2>/dev/null | redact > "$OUT"
    cat "$OUT"
    echo "# written to $OUT"
else
    report 2>/dev/null | redact
    echo "# NOTE: no writable path under /tmp; this report was not saved to a file"
fi
exit 0
