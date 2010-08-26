#!/usr/bin/env python
#
# this program is used to find source code that includes linux kernel headers directly
# (e.g. with #include <linux/...> or #include <asm/...>)
#
# then it lists

import sys, cpp, glob, os, re, getopt
import kernel
from utils import *
from defaults import *


def usage():
    print """\
  usage:  find_users.py [-v] (file|directory|@listfile)+

    this program is used to scan a list of files or directories for
    sources that include kernel headers directly. the program prints
    the list of said source files when it's done.

    when scanning directories, only files matching the following
    extension will be searched: .c .cpp .S .h

    use -v to enable verbose output
"""
    sys.exit(1)


try:
    optlist, args = getopt.getopt( sys.argv[1:], 'v' )
except:
    # unrecognized option
    print "error: unrecognized option"
    usage()

for opt, arg in optlist:
    if opt == '-v':
        kernel.verboseSearch = 1
        kernel.verboseFind   = 1
    else:
        usage()

if len(args) < 1:
    usage()

# helper function used to walk the user files
def parse_file(path, parser):
    parser.parseFile(path)


# first, obtain the list of kernel files used by our clients
# avoid parsing the 'kernel_headers' directory itself since we
# use this program with the Android source tree by default.
#
fparser = kernel.HeaderScanner()
walk_source_files( args, parse_file, fparser, excludes=["kernel_headers","original"] )
files   = fparser.getFiles()

for f in sorted(files):
    print f

sys.exit(0)
