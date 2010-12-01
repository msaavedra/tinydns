#!/usr/bin/env python2

import os
import sys
import time
import re
import argparse

import tinydns.data
import tinydns.dhcpd
from cross_platform import files

####################### Read command-line options #############################

parser = argparse.ArgumentParser(
    description='A utility to add dhcp-leased hosts to tinydns.'
    )
parser.add_argument(
    '-d', '--domain', nargs='?', required=True,
    help='''The domain to which hosts should belong. For example, if the
        domain is set to example.com then when the host jdoe is assigned
        an IP address via DHCP, it will be added to tinydns as
        jdoe.example.com.'''
    )
parser.add_argument(
    '--dry-run', action='store_true',
    help="Don't modify tinydns data. Write to standard output instead."
    )
parser.add_argument(
    '-l', '--leases', nargs='?', default='/var/lib/dhcpd/dhcpd.leases',
    help='The location of the dhcpd leases file (default: %(default)s).'
    )
parser.add_argument(
    '-m', '--macfile', nargs='?',
    help='''The path to a file of hard-coded MAC address to hostname mappings.
        Each line in the file should contain a MAC address, then any amount of
        whitespace, then the host name. This is useful for hosts that do not
        provide their name to the DHCP server.
    '''
    )
parser.add_argument(
    '-r', '--root', nargs='?', default='/etc/djbdns/tinydns',
    help='The tinydns root directory (default: %(default)s).'
    )
parser.add_argument(
    '-s', '--static', nargs='*',
    help='''Files that contain static tinydns host information. These will
        be concatenated with the DHCP-derived information to create the
        tinydns data file. Files may be specified one after another separated
        by spaces, or through the use of command-line wildcards (default:
        ROOT/*.static).'''
    )
options = parser.parse_args()
if options.static == None:
    options.static = []
    if os.path.exists(options.root):
        for item in os.listdir(options.root):
            if item.endswith('.static'):
                options.static.append(os.path.join(options.root, item))
while options.domain.startswith('.'):
    options.domain = options.domain[1:]

##### Set up tinydns authorized host data starting with the static info #######

dns = tinydns.data.Authority()
warning = tinydns.data.Section()
warning.add(tinydns.data.Comment(' DO NOT EDIT! ALL CHANGES WILL BE LOST!'))

dns.read_names(*options.static)
warning.add(
    tinydns.data.Comment(' This file is generated automatically from the following files.'),
    tinydns.data.Comment(' Edit them instead:')
    )
for file_name in options.static:
    warning.add(tinydns.data.Comment(file_name))

dns.prepend(warning)

############ Add data from the MAC file and from the DHCP leases ##############

CURRENT_TIME = time.time()
def calc_ttl(lease):
    ttl = int(lease.expiration - CURRENT_TIME)
    ttl = max(ttl, 60)
    ttl = min(ttl, 86400)
    return str(ttl)

dynamics = tinydns.data.Section()
msg = '%s DHCP-Leased records for the %s domain %s' % (
    '#' * 18,
    options.domain,
    '#' * 19
    )
dynamics.add(tinydns.data.Comment(msg))
leases = tinydns.dhcpd.Leases(options.leases)

mac_host_names = []
if options.macfile:
    for line in files.yield_lines(options.macfile):
        mac, host_name = line.split()
        mac = mac.strip()
        host_name.strip()
        mac_host_names.append(host_name)
        try:
            lease = leases[mac]
        except KeyError:
            continue
        domain_name = '%s.%s' % (host_name, options.domain)
        dynamics.add(tinydns.data.Alias(domain_name, lease.ip, ttl=calc_ttl(lease)))

for lease in leases.yield_unique():
    if lease.host_name != None and \
            lease.host_name not in mac_host_names:
        domain_name = '%s.%s' % (lease.host_name, options.domain)
        dynamics.add(tinydns.data.Alias(domain_name, lease.ip, ttl=calc_ttl(lease)))

dns.append(dynamics)

if options.dry_run:
    print dns
else:
    dns.merge(options.root)
    #tinydns.data.make(options.root)

