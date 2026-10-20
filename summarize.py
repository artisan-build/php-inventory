#!/usr/bin/env python3
"""Classify the PHP packages in php-inventory.sh reports into patch paths.

Runs on your workstation, not on the hosts: feed it the /tmp/php-inventory-*.txt
files the script left behind, collected together in one directory.

    python3 summarize.py reports/*.txt
    python3 summarize.py --tsv reports/

Classes
    STOCK-UBUNTU    distro package, so Canonical's USN is the patch. Says which
                    ESM channel that needs and whether Pro is attached.
    SURY-SUPPORTED  sury on jammy or noble, where ondrej still publishes.
    SURY-ORPHANED   sury on trusty, xenial or focal, which were dropped. Names
                    the self-build target.
    OTHER           source build, rpm, or a version string nothing recognises.
"""

import os
import re
import sys

# ---------------------------------------------------------------------------
# SUPPORT_DATA table
#
# Everything between here and END OF SUPPORT_DATA is a fact about the outside
# world rather than about your hosts, and it is the only part of this file that
# goes out of date on its own. Each table names the page that governs it, so a
# future reader can check the four of them and edit in place.
#
#   Ubuntu release and ESM dates   https://ubuntu.com/about/release-cycle
#   Releases ondrej/sury builds    https://deb.sury.org/
#   Freexian PHP LTS coverage      https://php.freexian.com/
#   Remi Collet backport branches  https://github.com/remicollet/php-src-security
#
# Last checked 2026-10-21.
# ---------------------------------------------------------------------------

# Canonical's support channel per release. esm-* needs an attached Ubuntu Pro
# subscription; "free" means standard security, no subscription needed.
# Source: https://ubuntu.com/about/release-cycle
UBUNTU_SUPPORT = {
    "trusty": ("esm-infra-legacy", "14.04"),
    "xenial": ("esm-infra-legacy", "16.04"),
    "bionic": ("esm-infra", "18.04"),
    "focal": ("esm-infra", "20.04"),
    "jammy": ("free", "22.04"),
    "noble": ("free", "24.04"),
    "resolute": ("free", "26.04"),
}

# ondrej/sury still builds EOL branches for these; the rest were dropped.
# Source: https://deb.sury.org/
SURY_LIVE = ("jammy", "noble")
SURY_DROPPED = ("trusty", "xenial", "focal")

# Freexian's paid PHP LTS covers Ubuntu 18.04 to 26.04, so not 14.04 or 16.04.
# Source: https://php.freexian.com/ (the support matrix on that page)
FREEXIAN_CODENAMES = ("bionic", "focal", "jammy", "noble", "resolute")

# Remi Collet's security backport branches. 7.2 is the odd one out: capital S.
# Source: https://github.com/remicollet/php-src-security
BACKPORT_BRANCH = {
    "5.6": "PHP-5.6-security-backports",
    "7.0": "PHP-7.0-security-backports",
    "7.1": "PHP-7.1-security-backports",
    "7.2": "PHP-7.2-Security-backports",
    "7.3": "PHP-7.3-security-backports",
    "7.4": "PHP-7.4-security-backports",
    "8.0": "PHP-8.0-security-backports",
    "8.1": "PHP-8.1-security-backports",
}
# Branches still maintained upstream: build from the php.net release, not a backport.
# Source: https://www.php.net/supported-versions.php
UPSTREAM_SUPPORTED = ("8.2", "8.3", "8.4", "8.5")

# --------------------------- END OF SUPPORT_DATA ---------------------------

SURY_MARKERS = ("deb.sury.org", "sury.org", "ondrej/php", "ondrej%2fphp")
UBUNTU_ARCHIVE_HOSTS = (
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "old-releases.ubuntu.com",
    "ports.ubuntu.com",
    "esm.ubuntu.com",
    ".ec2.archive.ubuntu.com",
    ".clouds.archive.ubuntu.com",
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_report(text):
    """Split one report into {section name: [lines]}."""
    sections = {}
    name = "HEADER"
    sections[name] = []
    for line in text.splitlines():
        if line.startswith("#### SECTION "):
            name = line[len("#### SECTION "):].strip()
            sections.setdefault(name, [])
        elif line.startswith("#### BEGIN") or line.startswith("#### END"):
            continue
        else:
            sections.setdefault(name, []).append(line)
    return sections


def kv(lines, key):
    prefix = key + ":"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def parse_os(sections):
    """Return (codename, version_id, os_id, pretty)."""
    lines = sections.get("OS", [])
    fields = {}
    for line in lines:
        if line.startswith("osrelease: "):
            body = line[len("osrelease: "):]
            if "=" in body:
                k, _, v = body.partition("=")
                fields[k.strip()] = v.strip().strip('"').strip("'")
    codename = (
        fields.get("VERSION_CODENAME")
        or fields.get("UBUNTU_CODENAME")
        or fields.get("DISTRIB_CODENAME")
        or kv(lines, "lsb_codename")
        or ""
    ).lower()
    version_id = fields.get("VERSION_ID") or fields.get("DISTRIB_RELEASE") or ""
    os_id = (fields.get("ID") or fields.get("DISTRIB_ID") or "").lower()
    pretty = fields.get("PRETTY_NAME") or fields.get("DISTRIB_DESCRIPTION") or ""

    system_release = kv(lines, "system_release")
    if system_release and not pretty:
        pretty = system_release
    if system_release and "amazon linux" in system_release.lower():
        os_id = os_id or "amzn"

    # 14.04 has no VERSION_CODENAME anywhere; fall back on the release number.
    if not codename and version_id:
        by_version = {v[1]: k for k, v in UBUNTU_SUPPORT.items()}
        codename = by_version.get(version_id, "")
    return codename, version_id, os_id, pretty


def parse_packages(sections):
    out = []
    for line in sections.get("PHP_PACKAGES", []):
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        manager, package, version, state = parts[0], parts[1], parts[2], parts[3]
        if state != "installed":
            continue
        out.append({"manager": manager, "package": package, "version": version})
    return out


def parse_origins(sections):
    """{package: [origin strings]} for the INSTALLED version only.

    apt-cache policy lists every candidate, so a stock jammy php8.1 whose
    version table also carries a newer sury build would look like a sury
    package if you read the whole block. Only the origins that follow the
    "***" marker, up to the next version entry, belong to what is installed.
    """
    origins = {}
    current = None
    in_installed = False
    for line in sections.get("PKG_ORIGIN", []):
        stripped = line.strip()
        if line.startswith("package: "):
            current = line[len("package: "):].strip()
            origins.setdefault(current, [])
            in_installed = False
        elif line.startswith("end_package:"):
            current = None
            in_installed = False
        elif stripped.startswith("origin_selected:"):
            in_installed = True
        elif stripped.startswith("version_entry:"):
            in_installed = False
        elif current and in_installed and stripped.startswith("origin:"):
            origins[current].append(stripped)
        elif line.startswith("yum\t"):
            parts = line.split("\t")
            if len(parts) >= 4:
                name = parts[1].split(".")[0]
                origins.setdefault(name, []).append("repo " + parts[3])
    return origins


def parse_pro(sections):
    """True / False / None (unknown)."""
    text = "\n".join(sections.get("PRO_STATUS", [])).lower()
    if not text.strip() or "not installed" in text:
        return None
    if "this machine is not attached" in text or "not attached" in text:
        return False
    if "account:" in text or "subscription:" in text or "valid until" in text:
        return True
    return None


def parse_running_series(sections):
    """PHP series with a running php-fpm master, plus apache mod_php series."""
    running = set()
    for line in sections.get("FPM_PROCESSES", []):
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        # Workers are not evidence on their own -- their master is -- but any
        # non-worker php-fpm process means that series is live.
        if not parts or parts[0] == "worker":
            continue
        blob = " ".join(parts[1:])
        m = re.search(r"/etc/php/(\d+\.\d+)/", blob)
        if not m:
            m = re.search(r"php-?fpm(\d+\.\d+)", blob)
        if not m:
            m = re.search(r"php(\d+\.\d+)-fpm", blob)
        if m:
            running.add(m.group(1))
        elif re.search(r"php5-fpm|/etc/php5/", blob):
            running.add("5")
    for line in sections.get("APACHE_MODPHP", []):
        if "no php module loaded" in line:
            continue
        # Apache names the module php5_module, php7_module or just php_module
        # -- never php8.1_module -- and only one can be loaded at a time, so
        # "some mod_php is live" is the most the module list can tell us.
        if re.search(r"mod:\s*php[0-9.]*_module", line):
            running.add("mod_php_any")
    return running


def series_of(package, version):
    m = re.match(r"^php(\d+\.\d+)-", package)
    if m:
        return m.group(1)
    if re.match(r"^(php5|libapache2-mod-php5)$", package) or package.startswith("php5-"):
        return "5"
    m = re.match(r"^libapache2-mod-php(\d+\.\d+)$", package)
    if m:
        return m.group(1)
    m = re.match(r"^(\d+\.\d+)", re.sub(r"^\d+:", "", version))
    if m:
        return m.group(1)
    return "?"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def self_build_target(series, codename, arch):
    if series in UPSTREAM_SUPPORTED:
        return ("build php-%s from the upstream php.net release for ubuntu %s (%s)"
                % (series, codename or "?", arch or "?"))
    branch = BACKPORT_BRANCH.get(series)
    if branch:
        return ("build remicollet/php-src-security %s for ubuntu %s (%s)"
                % (branch, codename or "?", arch or "?"))
    if series == "5.5":
        return ("NO upstream backport branch exists for 5.5 -- Canonical "
                "esm-infra-legacy php5 is the only patch path")
    return "no known backport branch for php-%s; needs a decision" % series


def classify(pkg, codename, arch, origins, pro_attached):
    package = pkg["package"]
    version = pkg["version"]
    origin_blob = " ".join(origins.get(package, [])).lower()
    vlow = version.lower()
    series = series_of(package, version)

    notes = []
    # The version string is the primary evidence. sury stamps every build with
    # "deb.sury.org"; the Ubuntu archive stamps "<n>ubuntu<n>", "+dfsg" or
    # "+esm". Origin is only consulted when the version says nothing, because
    # apt-cache policy also lists repositories the package did NOT come from.
    version_says_sury = any(m in vlow for m in SURY_MARKERS)
    version_says_ubuntu = (bool(re.search(r"\dubuntu\d", vlow))
                           or "+esm" in vlow or "+dfsg" in vlow)
    origin_says_sury = any(m in origin_blob for m in SURY_MARKERS)
    origin_says_ubuntu = any(h in origin_blob for h in UBUNTU_ARCHIVE_HOSTS)

    if pkg["manager"] in ("rpm", "yum"):
        return "OTHER", series, ["rpm package; patch path is the vendor's rpm repo, not Ubuntu or sury"]

    if version_says_sury:
        is_sury = True
    elif version_says_ubuntu:
        is_sury = False
    else:
        is_sury = origin_says_sury
    looks_ubuntu = version_says_ubuntu or (not is_sury and origin_says_ubuntu)
    from_ubuntu_host = origin_says_ubuntu

    if is_sury:
        if codename in SURY_LIVE:
            notes.append("ondrej/sury still publishes for %s: apt upgrade is the patch path"
                         % codename)
            return "SURY-SUPPORTED", series, notes
        if codename in SURY_DROPPED or codename == "":
            if codename == "":
                notes.append("host codename could not be read; treating sury as orphaned")
            else:
                notes.append("sury dropped %s; no upstream package will be published" % codename)
            if codename in FREEXIAN_CODENAMES:
                notes.append("Freexian PHP LTS covers %s: paid subscription is the alternative"
                             % codename)
            else:
                notes.append("Freexian PHP LTS does NOT cover %s: self-build is the only path"
                             % (codename or "this release"))
            notes.append("self-build: " + self_build_target(series, codename, arch))
            return "SURY-ORPHANED", series, notes
        notes.append("sury package on unexpected codename %r" % codename)
        notes.append("self-build: " + self_build_target(series, codename, arch))
        return "SURY-ORPHANED", series, notes

    if looks_ubuntu or from_ubuntu_host:
        channel, _ = UBUNTU_SUPPORT.get(codename, ("unknown", ""))
        if channel == "free":
            notes.append("%s is in standard security support: the USN is free, apt upgrade is enough"
                         % codename)
        elif channel in ("esm-infra", "esm-infra-legacy"):
            notes.append("needs Ubuntu Pro %s for %s" % (channel, codename))
            if pro_attached is True:
                notes.append("Pro IS attached on this host")
            elif pro_attached is False:
                notes.append("Pro is NOT attached: the USN cannot be installed until it is")
            else:
                notes.append("Pro attachment UNKNOWN (no pro client, or status unreadable)")
        else:
            notes.append("unrecognised codename %r: check the ESM channel by hand" % codename)
        if "+esm" in vlow:
            notes.append("already on an ESM build (%s)" % version)
        return "STOCK-UBUNTU", series, notes

    if origin_blob:
        notes.append("version string matches neither the Ubuntu archive nor sury, "
                     "and the origin does not either: source build or third-party repo")
        notes.append("origin: " + " | ".join(origins.get(package, [])[:3]))
    else:
        # The script only runs apt-cache policy for cli/fpm/mod_php packages,
        # so an extension or metapackage with an unmarked version has nothing
        # to classify from. Say that, rather than guess a source build.
        notes.append("undetermined: the version carries no archive or sury marker "
                     "and no origin was collected for this package; check by hand "
                     "with apt-cache policy " + package)
    return "OTHER", series, notes


def summarise_host(path, text):
    sections = parse_report(text)
    codename, version_id, os_id, pretty = parse_os(sections)
    host = kv(sections.get("HOST", []), "hostname") or "(unknown)"
    arch = kv(sections.get("HOST", []), "uname_m") or "?"
    pro = parse_pro(sections)
    origins = parse_origins(sections)
    running = parse_running_series(sections)
    packages = parse_packages(sections)

    rows = []
    for pkg in packages:
        cls, series, notes = classify(pkg, codename, arch, origins, pro)
        is_fpm = pkg["package"].endswith("-fpm") or pkg["package"] == "php5-fpm"
        is_modphp = pkg["package"].startswith("libapache2-mod-php")
        not_running = False
        if is_fpm:
            not_running = series not in running
        elif is_modphp:
            not_running = "mod_php_any" not in running
        rows.append({
            "package": pkg["package"],
            "version": pkg["version"],
            "series": series,
            "class": cls,
            "notes": notes,
            "not_running": not_running,
            "runtime_role": "fpm" if is_fpm else ("mod_php" if is_modphp else ""),
        })

    return {
        "path": path,
        "host": host,
        "arch": arch,
        "codename": codename,
        "version_id": version_id,
        "os_id": os_id,
        "pretty": pretty,
        "pro_attached": pro,
        "running_series": sorted(running),
        "rows": rows,
        "skipped": [l for l in sections.get("SKIPPED", []) if l and not l.startswith("#")],
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def pro_word(pro):
    return {True: "attached", False: "NOT attached", None: "unknown"}[pro]


def print_host(h, out=sys.stdout):
    out.write("=" * 78 + "\n")
    out.write("HOST %s   (%s)\n" % (h["host"], os.path.basename(h["path"])))
    out.write("  os:       %s  codename=%s  arch=%s\n"
              % (h["pretty"] or h["os_id"] or "?", h["codename"] or "?", h["arch"]))
    out.write("  pro:      %s\n" % pro_word(h["pro_attached"]))
    out.write("  running:  %s\n" % (", ".join(h["running_series"]) or "no php-fpm master, no mod_php"))
    if not h["rows"]:
        out.write("  no php packages installed\n")
    for r in h["rows"]:
        flag = "  [INSTALLED BUT NOT RUNNING]" if r["not_running"] else ""
        out.write("  - %-28s %-44s %s%s\n" % (r["package"], r["version"], r["class"], flag))
        for n in r["notes"]:
            out.write("      . %s\n" % n)
    for s in h["skipped"]:
        out.write("  skipped: %s\n" % s.replace("\t", ": "))


def print_fleet(hosts, out=sys.stdout):
    buckets = {}
    for h in hosts:
        for r in h["rows"]:
            buckets.setdefault(r["class"], []).append((h["host"], r))
    out.write("\n" + "=" * 78 + "\nFLEET SUMMARY\n" + "=" * 78 + "\n")
    for cls in ("SURY-ORPHANED", "OTHER", "STOCK-UBUNTU", "SURY-SUPPORTED"):
        items = buckets.get(cls, [])
        out.write("\n%s  (%d packages)\n" % (cls, len(items)))
        for host, r in items:
            out.write("  %-26s %-26s %s%s\n"
                      % (host, r["package"], r["version"],
                         "  [NOT RUNNING]" if r["not_running"] else ""))
    unknown_pro = [h["host"] for h in hosts if h["pro_attached"] is None]
    if unknown_pro:
        out.write("\nUbuntu Pro status unknown on: %s\n" % ", ".join(sorted(set(unknown_pro))))


def print_tsv(hosts, out=sys.stdout):
    out.write("host\tcodename\tarch\tpackage\tversion\tseries\tclass\trunning\tnotes\n")
    for h in hosts:
        for r in h["rows"]:
            out.write("\t".join([
                h["host"], h["codename"] or "?", h["arch"], r["package"], r["version"],
                r["series"], r["class"],
                "no" if r["not_running"] else "yes",
                "; ".join(r["notes"]),
            ]) + "\n")


def collect_paths(args):
    paths = []
    for a in args:
        if os.path.isdir(a):
            for name in sorted(os.listdir(a)):
                if name.endswith(".txt"):
                    paths.append(os.path.join(a, name))
        else:
            paths.append(a)
    return paths


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    tsv = "--tsv" in argv
    if not args:
        sys.stderr.write(__doc__ + "\n")
        return 2
    hosts = []
    for path in collect_paths(args):
        with open(path, "r") as fh:
            text = fh.read()
        if "#### BEGIN PHP-INVENTORY" not in text:
            sys.stderr.write("skipping %s: not a php-inventory report\n" % path)
            continue
        hosts.append(summarise_host(path, text))
    if not hosts:
        sys.stderr.write("no reports parsed\n")
        return 1
    if tsv:
        print_tsv(hosts)
    else:
        for h in hosts:
            print_host(h)
        print_fleet(hosts)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
