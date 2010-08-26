#!/usr/bin/python
#
# this tool is used to check that the syscall numbers that are in
# SYSCALLS.TXT correspond to those found in the Linux kernel sources
# for the arm and i386 architectures
#

import sys, re, string, os, commands
from   bionic_utils import *

# change this if necessary
syscalls_txt = "SYSCALLS.TXT"

def usage():
    print "usage: checksyscalls [options] [kernel_headers_rootdir]"
    print "    options:    -v   enable verbose mode"
    sys.exit(1)


linux_root    = None
syscalls_file = None

def parse_command_line(args):
    global linux_root, syscalls_file, verbose

    program = args[0]
    args    = args[1:]
    while len(args) > 0 and args[0][0] == "-":
        option = args[0][1:]
        args   = args[1:]

        if option == "v":
            D_setlevel(1)
        else:
            usage()

    if len(args) > 2:
        usage()

    if len(args) == 0:
        linux_root = find_kernel_headers()
        if linux_root == None:
            print "could not locate this system kernel headers root directory, please"
            print "specify one when calling this program, i.e. 'checksyscalls <headers-directory>'"
            sys.exit(1)
        print "using the following kernel headers root: '%s'" % linux_root
    else:
        linux_root = args[0]
        if not os.path.isdir(linux_root):
            print "the directory '%s' does not exist. aborting\n" % headers_root
            sys.exit(1)

parse_command_line(sys.argv)

syscalls_file = find_file_from_upwards(None, syscalls_txt)
if not syscalls_file:
    print "could not locate the %s file. Aborting" % syscalls_txt
    sys.exit(1)

print "parsing %s" % syscalls_file

# read the syscalls description file
#

parser = SysCallsTxtParser()
parser.parse_file(syscalls_file)
syscalls = parser.syscalls

re_nr_line       = re.compile( r"#define __NR_(\w*)\s*\(__NR_SYSCALL_BASE\+\s*(\w*)\)" )
re_nr_clock_line = re.compile( r"#define __NR_(\w*)\s*\(__NR_timer_create\+(\w*)\)" )
re_arm_nr_line   = re.compile( r"#define __ARM_NR_(\w*)\s*\(__ARM_NR_BASE\+\s*(\w*)\)" )
re_x86_line      = re.compile( r"#define __NR_(\w*)\s*([0-9]*)" )

# now read the Linux arm header
def process_nr_line(line,dict):

    m = re_nr_line.match(line)
    if m:
        dict[m.group(1)] = int(m.group(2))
        return

    m = re_nr_clock_line.match(line)
    if m:
        dict[m.group(1)] = int(m.group(2)) + 259
        return

    m = re_arm_nr_line.match(line)
    if m:
        #print "%s = %s" % (m.group(1), m.group(2))
        dict["ARM_"+m.group(1)] = int(m.group(2)) + 0x0f0000
        return

    m = re_x86_line.match(line)
    if m:
        # try block because the ARM header has some #define _NR_XXXXX  /* nothing */
        try:
            #print "%s = %s" % (m.group(1), m.group(2))
            dict[m.group(1)] = int(m.group(2))
        except:
            pass
        return


def process_header(header_file,dict):
    fp = open(header_file)
    D("reading "+header_file)
    for line in fp.xreadlines():
        line = line.strip()
        if not line: continue
        process_nr_line(line,dict)
    fp.close()

arm_dict = {}
x86_dict = {}


# remove trailing slash and '/include' from the linux_root, if any
if linux_root[-1] == '/':
    linux_root = linux_root[:-1]

if len(linux_root) > 8 and linux_root[-8:] == '/include':
    linux_root = linux_root[:-8]

arm_unistd = linux_root + "/include/asm-arm/unistd.h"
if not os.path.exists(arm_unistd):
    print "WEIRD: could not locate the ARM unistd.h header file"
    print "tried searching in '%s'" % arm_unistd
    print "maybe using a different set of kernel headers might help"
    sys.exit(1)

# on recent kernels, asm-i386 and asm-x64_64 have been merged into asm-x86
# with two distinct unistd_32.h and unistd_64.h definition files.
# take care of this here
#
x86_unistd = linux_root + "/include/asm-i386/unistd.h"
if not os.path.exists(x86_unistd):
    x86_unistd1 = x86_unistd
    x86_unistd = linux_root + "/include/asm-x86/unistd_32.h"
    if not os.path.exists(x86_unistd):
        print "WEIRD: could not locate the i386/x86 unistd.h header file"
        print "tried searching in '%s' and '%s'" % (x86_unistd1, x86_unistd)
        print "maybe using a different set of kernel headers might help"
        sys.exit(1)

process_header( linux_root+"/include/asm-arm/unistd.h", arm_dict )
process_header( x86_unistd, x86_dict )

# now perform the comparison
errors = 0
for sc in syscalls:
    sc_name = sc["name"]
    sc_id   = sc["id"]
    if sc_id >= 0:
        if not arm_dict.has_key(sc_name):
            print "arm syscall %s not defined !!" % sc_name
            errors += 1
        elif arm_dict[sc_name] != sc_id:
            print "arm syscall %s should be %d instead of %d !!" % (sc_name, arm_dict[sc_name], sc_id)
            errors += 1

for sc in syscalls:
    sc_name = sc["name"]
    sc_id2  = sc["id2"]
    if sc_id2 >= 0:
        if not x86_dict.has_key(sc_name):
            print "x86 syscall %s not defined !!" % sc_name
            errors += 1
        elif x86_dict[sc_name] != sc_id2:
            print "x86 syscall %s should be %d instead of %d !!" % (sc_name, x86_dict[sc_name], sc_id2)
            errors += 1

if errors == 0:
    print "congratulations, everything's fine !!"
else:
    print "correct %d errors !!" % errors
