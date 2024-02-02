#!/usr/bin/env python

#
# Convert IP list to CDB list
# Copyright (C) 2016 Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#

import re
from sys import exit, argv

# CIDR conversion for converting ip ranges to cdb list compatible ranges
cdir_conversion = {"32": 4, "24": 3, "16": 2, "8": 1}

def calculate_ips(ip, mask):
    # Get the increment of the current ip range, this will be the amount subnets we create
    increment = 2^mask
    # Set octets we will be working in
    if 0 < mask < 8:
        octet = 1
    elif 8 < mask < 16:
        octet = 2
    elif 16 < mask < 24:
        octet = 3
    else:
        octet = 4

    # Go up one mask for subnetting
    round_up_mask = 8 * ((8+mask) // 8)
    
    # Append first ip to iplist
    if mask < 24:
        iplist.append(('.'.join(ip[:cdir_conversion[round_up_mask]]) + ".:") )
    else:
        iplist.append('.'.join(ip[:cdir_conversion[round_up_mask]]) + ":")
    # Loop to generate the IPs
    for _ in range(increment):
        if mask < 24:
            # Add one to the ip address octet we're working in
            ip[octet-1] = ip[octet-1] + 1
            # Add the added subnet to the iplist
            iplist.append('.'.join(ip[:cdir_conversion[round_up_mask]]) + ".:")   
        else:
            # Add one to the ip address octet we're working in
            ip[octet-1] = ip[octet-1] + 1
            # Add the added subnet to the iplist
            iplist.append('.'.join(ip[:cdir_conversion[round_up_mask]]) + ":")
    return iplist

try:
    if len(argv) != 3:
        print("Bad arguments. Try: iplist-to-cdblist.py input output")
        exit(1)

    # Splits address and subnet mask
    ip_regex = re.compile("^((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:/(\d{1,2}){0,1}|)")
    first_time = True
    

    # Open ouptut file fo writing
    fo = open(argv[2], 'w')

    # Open the input file and check each line
    with open(argv[1]) as f:
        for line in f:
            # Split with regex
            match = ip_regex.match(line.rstrip('\r\n'))

            if not match:  # Read just lines that start with an IP
                continue

            ip = match.group(1)
            mask = int(match.group(2))

            if mask:  
                # split ip into an array
                ip = ip.split('.')
                # Convert allowed masks (32, 24, 16, 8)
                if mask in cdir_conversion:
                    # Will make it look like this: 1.1.1
                    ip = '.'.join(ip[:cdir_conversion[mask]])
                    if mask != "32":
                        ip += "."
                # Add functionality for other masks above 8
                elif 0 < mask < 32:
                    iplist = calculate_ips(ip, mask)
                # Make sure a bogus mask isn't passed
                else:
                    continue

            ip += ":"  # CDB List format

            if first_time:
                if iplist:
                    # prevents the addition of an accidental new line
                    first_time_list = True
                    for ip_add in iplist:
                        if first_time_list:
                            fo.write(ip_add)
                            first_time_list = False
                        else:
                            fo.write("\n" + ip_add)
                else:
                    fo.write(ip)
                first_time = False
            else:
                if iplist:
                    for ip_add in iplist:
                        fo.write("\n" + ip_add)
                else:
                    fo.write("\n" + ip)

    fo.close()

    print("[{0}] -> [{1}]".format(argv[1], argv[2]))

except Exception as e:
    print("Error:\n{0}\nExiting...".format(e))
    exit(1)
