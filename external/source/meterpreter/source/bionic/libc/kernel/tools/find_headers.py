#!/usr/bin/env python
#
# this program is used to find source code that includes linux kernel headers directly
# (e.g. with #include <linux/...> or #include <asm/...>)
#
# then it lists

import sys, cpp, glob, os, re, getopt, kernel
from utils import *
from defaults import *

program_dir = find_program_dir()

wanted_archs   = kernel_archs
wanted_include = os.path.normpath(program_dir + '/../original')
wanted_config  = os.path.normpath(program_dir + '/../original/config')

def usage():
    print """\
  usage:  find_headers.py [options] (file|directory|@listfile)+

     options:
        -d <include-dir>   specify alternate kernel headers
                           'include' directory
                           ('%s' by default)

        -c <file>          specify alternate .config file
                           ('%s' by default)

        -a <archs>         used to specify an alternative list
                           of architectures to support
                           ('%s' by default)

        -v                 enable verbose mode

    this program is used to find all the kernel headers that are used
    by a set of source files or directories containing them. the search
    is recursive to find *all* required files.

""" % ( wanted_include, wanted_config, string.join(kernel_archs,",") )
    sys.exit(1)


try:
    optlist, args = getopt.getopt( sys.argv[1:], 'vc:d:a:' )
except:
    # unrecognized option
    print "error: unrecognized option"
    usage()

for opt, arg in optlist:
    if opt == '-a':
        wanted_archs = string.split(arg,',')
    elif opt == '-d':
        wanted_include = arg
    elif opt == '-c':
        wanted_config = arg
    elif opt == '-v':
        kernel.verboseSearch = 1
        kernel.verboseFind   = 1
        verbose = 1
    else:
        usage()

if len(args) < 1:
    usage()

kernel_root = wanted_include
if not os.path.exists(kernel_root):
    sys.stderr.write( "error: directory '%s' does not exist\n" % kernel_root )
    sys.exit(1)

if not os.path.isdir(kernel_root):
    sys.stderr.write( "error: '%s' is not a directory\n" % kernel_root )
    sys.exit(1)

if not os.path.isdir(kernel_root+"/linux"):
    sys.stderr.write( "error: '%s' does not have a 'linux' directory\n" % kernel_root )
    sys.exit(1)

if not os.path.exists(wanted_config):
    sys.stderr.write( "error: file '%s' does not exist\n" % wanted_config )
    sys.exit(1)

if not os.path.isfile(wanted_config):
    sys.stderr.write( "error: '%s' is not a file\n" % wanted_config )
    sys.exit(1)

# find all architectures in the kernel tree
re_asm_ = re.compile(r"asm-(\w+)")
archs   = []
for dir in os.listdir(kernel_root):
    m = re_asm_.match(dir)
    if m:
        if verbose: print ">> found kernel arch '%s'" % m.group(1)
        archs.append(m.group(1))

# if we're using the 'kernel_headers' directory, there is only asm/
# and no other asm-<arch> directories (arm is assumed, which sucks)
#
in_kernel_headers = False
if len(archs) == 0:
    # this can happen when we're using the 'kernel_headers' directory
    if os.path.isdir(kernel_root+"/asm"):
        in_kernel_headers = True
        archs = [ "arm" ]

# if the user has specified some architectures with -a <archs> ensure that
# all those he wants are available from the kernel include tree
if wanted_archs != None:
    if in_kernel_headers and wanted_archs != [ "arm" ]:
        sys.stderr.write( "error: when parsing kernel_headers, 'arm' architecture only is supported at the moment\n" )
        sys.exit(1)
    missing = []
    for arch in wanted_archs:
        if arch not in archs:
            missing.append(arch)
    if len(missing) > 0:
        sys.stderr.write( "error: the following requested architectures are not in the kernel tree: " )
        for a in missing:
            sys.stderr.write( " %s" % a )
        sys.stderr.write( "\n" )
        sys.exit(1)

    archs = wanted_archs

# helper function used to walk the user files
def parse_file(path, parser):
    parser.parseFile(path)


# remove previous destination directory
#destdir = "/tmp/bionic-kernel-headers/"
#cleanup_dir(destdir)

# try to read the config file
try:
    cparser = kernel.ConfigParser()
    cparser.parseFile( wanted_config )
except:
    sys.stderr.write( "error: can't parse '%s'" % wanted_config )
    sys.exit(1)

kernel_config = cparser.getDefinitions()

# first, obtain the list of kernel files used by our clients
fparser = kernel.HeaderScanner()
walk_source_files( args, parse_file, fparser, excludes=["kernel_headers"] )
headers = fparser.getHeaders()
files   = fparser.getFiles()

# now recursively scan the kernel headers for additionnal sub-included headers
hparser = kernel.KernelHeaderFinder(headers,archs,kernel_root,kernel_config)
headers = hparser.scanForAllArchs()

if 0:    # just for debugging
    dumpHeaderUsers = False

    print "the following %d headers:" % len(headers)
    for h in sorted(headers):
        if dumpHeaderUsers:
            print "  %s (%s)" % (h, repr(hparser.getHeaderUsers(h)))
        else:
            print "  %s" % h

    print "are used by the following %d files:" % len(files)
    for f in sorted(files):
        print "  %s" % f

    sys.exit(0)

for h in sorted(headers):
    print h

sys.exit(0)
