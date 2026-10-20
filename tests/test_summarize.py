#!/usr/bin/env python3
"""Fixture tests for summarize.py.

    python3 -m unittest discover -s tests

Fixtures under tests/fixtures/ are php-inventory.sh output with every host
detail swapped for an invented one. The container- prefixed files came from
the docker test matrix; the rest are hand-built for situations a container
cannot reproduce, such as an attached Pro subscription or sury-on-focal.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, os.path.dirname(HERE))

import summarize  # noqa: E402


def load(name):
    path = os.path.join(FIXTURES, name)
    with open(path) as fh:
        return summarize.summarise_host(path, fh.read())


def rows_by_package(host):
    return {r["package"]: r for r in host["rows"]}


class ClassificationTest(unittest.TestCase):

    def assert_class(self, host, package, expected):
        rows = rows_by_package(host)
        self.assertIn(package, rows, "%s not in report" % package)
        self.assertEqual(expected, rows[package]["class"],
                         "%s was classified %s" % (package, rows[package]["class"]))
        return rows[package]

    def notes(self, row):
        return " ".join(row["notes"])

    # -- STOCK-UBUNTU ------------------------------------------------------

    def test_trusty_php5_is_stock_needing_esm_infra_legacy(self):
        host = load("trusty-stock-php5.txt")
        self.assertEqual("trusty", host["codename"])
        row = self.assert_class(host, "php5-fpm", "STOCK-UBUNTU")
        self.assertIn("esm-infra-legacy", self.notes(row))
        self.assertNotIn("esm-infra for", self.notes(row))

    def test_trusty_reports_pro_attached(self):
        host = load("trusty-stock-php5.txt")
        self.assertIs(True, host["pro_attached"])
        self.assertIn("Pro IS attached", self.notes(rows_by_package(host)["php5-fpm"]))

    def test_focal_stock_php74_needs_esm_infra_and_flags_missing_pro(self):
        host = load("focal-sury-mixed.txt")
        row = self.assert_class(host, "php7.4-fpm", "STOCK-UBUNTU")
        self.assertIn("esm-infra for focal", self.notes(row))
        self.assertIn("Pro is NOT attached", self.notes(row))
        self.assertIs(False, host["pro_attached"])

    def test_jammy_stock_php81_is_free_despite_sury_in_the_version_table(self):
        # The container had the ondrej PPA enabled, so apt-cache policy lists a
        # newer sury build for a package that came from the Ubuntu archive.
        host = load("container-jammy-stock-and-sury.txt")
        row = self.assert_class(host, "php8.1-fpm", "STOCK-UBUNTU")
        self.assertIn("standard security support", self.notes(row))

    # -- SURY --------------------------------------------------------------

    def test_jammy_sury_php74_is_supported(self):
        host = load("container-jammy-stock-and-sury.txt")
        row = self.assert_class(host, "php7.4-fpm", "SURY-SUPPORTED")
        self.assertIn("still publishes", self.notes(row))

    def test_noble_sury_is_supported(self):
        host = load("noble-sury.txt")
        self.assert_class(host, "php7.3-fpm", "SURY-SUPPORTED")

    def test_xenial_sury_is_orphaned_and_names_the_backport_branch(self):
        host = load("xenial-sury-orphan.txt")
        row = self.assert_class(host, "php7.2-fpm", "SURY-ORPHANED")
        # 7.2 is the branch with the capital S.
        self.assertIn("PHP-7.2-Security-backports", self.notes(row))
        self.assertIn("ubuntu xenial", self.notes(row))
        self.assertIn("does NOT cover xenial", self.notes(row))

    def test_xenial_php56_names_its_own_branch(self):
        host = load("xenial-sury-orphan.txt")
        row = self.assert_class(host, "php5.6-fpm", "SURY-ORPHANED")
        self.assertIn("PHP-5.6-security-backports", self.notes(row))

    def test_focal_sury_php83_is_orphaned_but_freexian_covers_focal(self):
        host = load("focal-sury-mixed.txt")
        row = self.assert_class(host, "php8.3-fpm", "SURY-ORPHANED")
        self.assertIn("Freexian PHP LTS covers focal", self.notes(row))
        # 8.3 is still supported upstream, so there is no backport branch to build.
        self.assertIn("upstream php.net release", self.notes(row))
        self.assertNotIn("php-src-security", self.notes(row))

    # -- OTHER -------------------------------------------------------------

    def test_amazon_linux_rpm_is_other(self):
        host = load("container-amazonlinux-rpm.txt")
        php_rows = [r for r in host["rows"] if r["package"].startswith("php")]
        self.assertTrue(php_rows, "no php rpm packages in the fixture")
        for row in php_rows:
            self.assertEqual("OTHER", row["class"], row["package"])

    # -- installed but not running ----------------------------------------

    def test_installed_but_not_running_is_flagged(self):
        host = load("focal-sury-mixed.txt")
        rows = rows_by_package(host)
        self.assertTrue(rows["php7.4-fpm"]["not_running"],
                        "php7.4-fpm has no master and should be flagged")
        self.assertFalse(rows["php8.3-fpm"]["not_running"],
                         "php8.3-fpm has a running master")

    def test_mod_php_counts_as_running(self):
        host = load("trusty-stock-php5.txt")
        rows = rows_by_package(host)
        self.assertFalse(rows["libapache2-mod-php5"]["not_running"],
                         "apache reports php5_module loaded")
        self.assertFalse(rows["php5-fpm"]["not_running"])

    # -- redaction ---------------------------------------------------------

    def test_no_fixture_leaks_the_planted_credential(self):
        for name in sorted(os.listdir(FIXTURES)):
            with open(os.path.join(FIXTURES, name)) as fh:
                body = fh.read()
            self.assertNotIn("SECRET", body, "%s leaks the planted credential" % name)
            self.assertNotIn("user:", body, "%s leaks a userinfo component" % name)


class ParsingTest(unittest.TestCase):

    def test_origins_are_scoped_to_the_installed_version(self):
        with open(os.path.join(FIXTURES, "container-jammy-stock-and-sury.txt")) as fh:
            sections = summarize.parse_report(fh.read())
        origins = summarize.parse_origins(sections)
        blob = " ".join(origins.get("php8.1-fpm", []))
        self.assertNotIn("ondrej", blob,
                         "the sury candidate leaked into the installed origins")

    def test_skipped_sections_survive_a_non_root_run(self):
        host = load("container-jammy-nonroot.txt")
        self.assertTrue(host["skipped"], "a non-root run should record skips")

    def test_report_without_php_parses_to_no_rows(self):
        host = load("container-trusty-stock-php5.txt")
        self.assertEqual("trusty", host["codename"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
