#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import setuptools.command.sdist
import os
import sys
import platform
import imp
import argparse

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 5, 2):
    sys.exit("Error: Electron Cash requires Python version >= 3.5.2...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--user', dest='is_user', action='store_true', default=False)
    parser.add_argument('--system', dest='is_user', action='store_false', default=False)
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    parser.add_argument('--prefix=', dest='prefix_path', metavar='prefix', nargs='?', const='/', default=sys.prefix)
    opts, _ = parser.parse_known_args(sys.argv[1:])

    # Use per-user */share directory if the global one is not writable or if a per-user installation
    # is attempted
    user_share   = os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
    system_share = os.path.join(opts.prefix_path, "share")
    if not opts.is_user:
        # Not neccarily a per-user installation try system directories
        if os.access(opts.root_path + system_share, os.W_OK):
            # Global /usr/share is writable for us – so just use that
            share_dir = system_share
        elif not os.path.exists(opts.root_path + system_share) and os.access(opts.root_path, os.W_OK):
            # Global /usr/share does not exist, but / is writable – keep using the global directory
            # (happens during packaging)
            share_dir = system_share
        else:
            # Neither /usr/share (nor / if /usr/share doesn't exist) is writable, use the
            # per-user */share directory
            share_dir = user_share
    else:
        # Per-user installation
        share_dir = user_share
    data_files += [
        # Menu icon
        (os.path.join(share_dir, 'icons/hicolor/128x128/apps/'), ['icons/electron-cash.png']),
        (os.path.join(share_dir, 'pixmaps/'),                    ['icons/electron-cash.png']),
        # Menu entry
        (os.path.join(share_dir, 'applications/'), ['electron-cash.desktop']),
        # App stream (store) metadata
        (os.path.join(share_dir, 'metainfo/'), ['org.electroncash.ElectronCash.appdata.xml']),
    ]

class MakeAllBeforeSdist(setuptools.command.sdist.sdist):
    """Does some custom stuff before calling super().run()."""

    user_options = setuptools.command.sdist.sdist.user_options + [
        ("disable-secp", None, "Disable libsecp256k1 complilation (default)."),
        ("enable-secp", None, "Enable libsecp256k1 complilation."),
        ("disable-zbar", None, "Disable libzbar complilation (default)."),
        ("enable-zbar", None, "Enable libzbar complilation.")
    ]

    def initialize_options(self):
        self.disable_secp = None
        self.enable_secp = None
        self.disable_zbar = None
        self.enable_zbar = None
        super().initialize_options()

    def finalize_options(self):
        if self.enable_secp is None:
            self.enable_secp = False
        self.enable_secp = not self.disable_secp and self.enable_secp
        if self.enable_zbar is None:
            self.enable_zbar = False
        self.enable_zbar = not self.disable_zbar and self.enable_zbar
        super().finalize_options()

    def run(self):
        """Run command."""
        #self.announce("Running make_locale...")
        #0==os.system("contrib/make_locale") or sys.exit("Could not make locale, aborting")
        #self.announce("Running make_packages...")
        #0==os.system("contrib/make_packages") or sys.exit("Could not make locale, aborting")
        if self.enable_secp:
            self.announce("Running make_secp...")
            0==os.system("contrib/make_secp") or sys.exit("Could not build libsecp256k1")
        if self.enable_zbar:
            self.announce("Running make_zbar...")
            0==os.system("contrib/make_zbar") or sys.exit("Could not build libzbar")
        super().run()

setup(
    cmdclass={
        'sdist': MakeAllBeforeSdist,
    },
    name="Electron Cash",
    version=version.PACKAGE_VERSION,
    install_requires=requirements + ['pyqt5'],
    extras_require={
        'hardware': requirements_hw,
    },
    packages=[
        'electroncash',
        'electroncash.qrreaders',
        'electroncash.utils',
        'electroncash_gui',
        'electroncash_gui.qt',
        'electroncash_gui.qt.qrreader',
        'electroncash_gui.qt.utils',
        'electroncash_plugins',
        'electroncash_plugins.audio_modem',
        'electroncash_plugins.cosigner_pool',
        'electroncash_plugins.email_requests',
        'electroncash_plugins.hw_wallet',
        'electroncash_plugins.keepkey',
        'electroncash_plugins.labels',
        'electroncash_plugins.ledger',
        'electroncash_plugins.trezor',
        'electroncash_plugins.digitalbitbox',
        'electroncash_plugins.virtualkeyboard',
        'electroncash_plugins.shuffle',
    ],
    package_dir={
        'electroncash': 'lib',
        'electroncash_gui': 'gui',
        'electroncash_plugins': 'plugins',
    },
    package_data={
        'electroncash': [
            'servers.json',
            'servers_testnet.json',
            'currencies.json',
            'www/index.html',
            'wordlist/*.txt',
            'libsecp256k1*',
            'libzbar*',
            'locale/*/LC_MESSAGES/electron-cash.mo',
        ],
        'electroncash_plugins.shuffle' : [
            'servers.json',
            'protobuf/*.proto'
        ]
    },
    scripts=['electron-cash'],
    data_files=data_files,
    description="Lightweight Bitcoin Cash Wallet",
    author="Jonald Fyookball",
    author_email="jonf@electroncash.org",
    license="MIT Licence",
    url="http://electroncash.org",
    long_description="""Lightweight Bitcoin Cash Wallet"""
)
