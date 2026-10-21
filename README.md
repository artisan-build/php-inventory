# php-inventory

This script will help you identify what version(s) of PHP are running on your servers, what operating system your server is running, and where your PHP binary came from. It was created in response to the announcement of a critical security vulnerability due to be patched on October 21, 2026. No details were publicly disclosed when the announcement was made that the patch was on its way, but there were indications that version back to 5.4 were impacted.

This led me to check in with my clients. I know some of them are running some legacy PHP apps on EOL versions of PHP and older Linux distributions. The question I needed to answer for them was whether a patched version of their PHP was going to be available to deploy. The answers turned out to be pretty mixed.

This may not run everywhere. We built it in response to our own needs. While we tried to make it support as many environments as possible, we were in a hurry. So if you are running a pre-14 version of Ubuntu or some 1990s boutique distribution of Linux, it might not do what you need. But for the vast majority of servers provisioned by hosting providers, it should work fine.

## Why the origin decides the patch path

PHP 7.4 went end of life upstream in November 2022, and several people kept patching it anyway, on
different terms.

Some people and organizations build PHP past the end of the official security update period, but they do so for specific environments and on various terms. Some are free, and some are paid products. The original installation channel for PHP on an old server might no longer be the source of a patch for this vulnerability, so figuring out where to source a patched binary for your server becomes your job.

The good news is that AI is really good at identifying reliable sources for you. If you can tell your coding agent what your OS is, what version of PHP you're running, and how it was originally installed, it can point you at the best option. The bad news is that sometimes that best option (or only option) is to build it yourself.

The point of this script is to gather the relevant information from all of your servers. Run as root, it gives you everything your coding agent will need. Run without root, and it will still work, but will leave out some details that might be relevant in some situations. Your agent will let you know when it sees the output whether you need to escalate and run it again.

## What the report covers

One text file per host, sectioned under `#### SECTION` headers so you can grep it. It records:

- the OS release, codename and kernel
- every PHP package dpkg or rpm knows about, with version and install state
- for each php-cli, php-fpm and mod_php package, the whole `apt-cache policy` origin table, or the
  yum repository
- the configured apt sources, including `sources.list.d`
- Ubuntu Pro status
- every PHP binary on `$PATH` and in the usual prefixes, with `php -v`, its `Configure Command` and
  its `php -m` module list
- running php-fpm processes, split into masters and pool workers
- fpm pool configuration, with each pool's `listen`
- whether Apache has a mod_php loaded
- listening TCP sockets
- running containers, when docker is installed and reachable
- a SKIPPED section naming every section it could not finish and why, so a thin report never passes
  for an empty one

## Running it

Copy the script to the host and run it. Either of these works:

```sh
curl -fsSLO https://raw.githubusercontent.com/artisan-build/php-inventory/main/php-inventory.sh
sudo sh php-inventory.sh
```

```sh
scp php-inventory.sh user@host:
ssh user@host 'sudo sh php-inventory.sh'
```

It prints the report and writes the same text to `/tmp/php-inventory-<hostname>.txt`. It exits 0,
prints nothing to stderr, never prompts, and takes a few seconds. If another user has already run it
there, their file is left alone and yours goes to `/tmp/php-inventory-<hostname>-<uid>.txt`. The last
line of the output always names the file it wrote.

Ubuntu 14.04 and newer work. The script is `/bin/sh`, needs no jq, and avoids the awk interval syntax
that mawk 1.3.3 on trusty does not implement, so it runs on hosts too old for most tooling. Debian
behaves the same as Ubuntu. On Amazon Linux and other RHEL-family hosts it falls back to rpm and yum,
which gives you packages, versions and repository names but no apt origin table; on an rpm host with
no yum, the origin cannot be recovered at all and the report says so.

### Without root

It runs as any user. Without root you lose:

- `sources.list.d` files that only root can read, listed as `(unreadable as this user)`
- the Apache module list, because `apache2ctl -M` normally needs root
- the executable behind another user's php-fpm master, read from `/proc/<pid>/exe`
- the process names behind listening sockets, which `ss -ltnp` and `netstat -ltnp` show only to root
- fpm pool configuration files with restrictive permissions
- `docker ps`, which needs root or membership of the `docker` group

The package list, the origins, the PHP binaries and the fpm process list are the same either way.
Every gap above is written into the SKIPPED section with its reason.

## What it does not do

It installs nothing, starts and stops nothing, and changes no configuration. The only thing it writes
is its own report under `/tmp`, plus two scratch files there that it removes on exit.

It opens no network connections of its own: no curl, no wget, no `apt-get update`. Two commands it
shells out to can reach the network on some systems, and both belong to someone else. `pro status` is
Canonical's Ubuntu Pro client and may contact Canonical to work out what a host is entitled to.
`yum list installed` can refresh repository metadata on older yum. `apt-cache policy` reads the local
apt cache and nothing else. Nothing in the script sends your report anywhere, so moving the files off
the host is your job.

## What it redacts

The whole report passes through one filter on its way to stdout and the file, so no section can get a
credential past it.

Credentials in a URI become `scheme://REDACTED@host`. That is the case this exists for: Ubuntu Pro
writes `https://bearer:TOKEN@esm.ubuntu.com` lines into `sources.list.d`, and an ESM-attached host
would otherwise print its contract token in the APT_SOURCES section. A value following `token`,
`password`, `passwd`, `secret`, `bearer` or `api_key` becomes `REDACTED-SECRET`.

Read a report before you send it on. Hostnames, pool names, socket paths and configuration paths are
not redacted, because they are the information the report exists to carry.

## Summarising many hosts

Collect the files into one directory, then:

```sh
python3 summarize.py reports/*.txt
python3 summarize.py reports/                      # a directory works too
python3 summarize.py --tsv reports/ > inventory.tsv
```

You get a block per host and a fleet summary that buckets every package by class, orphans first.
There are four classes.

`STOCK-UBUNTU` came from the Ubuntu archive, so Canonical's USN is the patch. The note says which ESM
channel that release needs and whether Pro is attached on the host, which is the difference between
running `apt upgrade` and buying a subscription first.

`SURY-SUPPORTED` came from sury on a release sury still builds for, currently jammy and noble.
`apt upgrade` is the patch path.

`SURY-ORPHANED` came from sury on a release sury dropped: trusty, xenial or focal. Nobody upstream
will publish this fix. The note says whether Freexian's paid PHP LTS covers that release, and names
the self-build target, which is the php.net release for a branch PHP still supports or the matching
`remicollet/php-src-security` backport branch for one it does not.

`OTHER` is everything left: an rpm, a source build, or a version string carrying no marker the
summariser recognises. These need a person to look at them.

A package is also flagged `[INSTALLED BUT NOT RUNNING]` when nothing is serving it, meaning an fpm
package whose series has no master process, or a mod_php package with no module loaded in Apache.
Those are often the cheapest things on the list, because the fix is to remove the package.

The release and support data the classifier uses is hardcoded in one block near the top of
`summarize.py`, marked `SUPPORT_DATA`, with a source URL for each table. It was last checked on
2026-10-21.

## Limits

PHP inside a container is invisible to a report taken on the host. You get the container's image name
and little else, so containerised PHP has to be inventoried from inside the container by running the
script there.

"Not running" means "not running at the moment the script ran". A service stopped for maintenance,
or one that only starts under load, reads the same as one nobody has used in two years.

A statically built PHP is not found, and neither is a PHP installed outside `/usr/bin`,
`/usr/local/bin`, the sbin equivalents, `/opt/php*/bin`, `/opt/*/php*/bin`, `/usr/local/php*/bin` and
the directories on `$PATH`. If a host clearly serves PHP and the report says there is none, that is
what to go looking for.

The summariser reads the version string first and the origin table second, because `apt-cache policy`
lists repositories a package could have come from next to the one it did. A package whose version
carries no marker and for which no origin was collected is reported as undetermined rather than
guessed at.

## What to do with the results

The patch paths themselves, including how to build a backport, are written up at
<https://scalpels.app/guides/patch-php-on-your-servers>.

## License

MIT. See [LICENSE](LICENSE).
