#!/usr/bin/env python
#
#   Copyright (c) 2014, Are Hansen - Honeypot Development
# 
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without modification, are
#   permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
# 
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or other
#   materials provided with the distribution.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
#   WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


__autor__ = 'Are Hansen'
__date__ = '2014, October 10'
__version__ = 'DEV 0.0.3'


import sys

newlog = []
loglines = []


# Read lines from the firewall logs,
with open(sys.argv[1], 'r') as lines:
    for line in lines.readlines():
        # create a list object of each line and 
        # append the list object to loglines.
        loglines.append(line.rstrip().split())


# Remove any empty indexes
for index in loglines:
    # and append them to the newlog list object.
    newlog.append(filter(None, index))


# Itterate over the newlog list object and extract the data
# thats used for building a lostalgic formatted log file.
for log in newlog:
    # Timestamp format: DayOfMonth/NameOfMonth/YEAR:TimeOfDay
    date = '[{0}/{1}/2014:{2} +0200]'.format(log[1], log[0], log[2])

    for tag in log:
        if 'ALLOW' in tag:
            action = 'ACCEPT'

        if 'BLOCK' in tag:
            action = 'BLOCK'

        if 'SRC=' in tag:
            src = tag.split('=')[1]

        if 'DST=' in tag:
            dst = tag.split('=')[1]

        if 'PROTO=' in tag:
            proto = tag.split('=')[1]

        if 'DPT' in tag:
            dpt = tag.split('=')[1]

    print '{0} - - {1} "POST {2}-{4} {5}" {5} 200'.format(src, date, action, proto.lower(), 
                                                          dpt, dst)

"""
logstalgia 1280x800 -u 1 -f --glow-duration 1.0 --hide-paddle -s 10 \
-g "BLOCKED ====================================,BLOCK,49" \
-g "ALLOWED ====================================,ACCEPT,49"
"""
