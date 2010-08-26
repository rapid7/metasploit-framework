# this file contains definitions related to the Linux kernel itself
#

# list here the macros that you know are always defined/undefined when including
# the kernel headers
#
import sys, cpp, re, os.path, string, time
from defaults import *

verboseSearch = 0
verboseFind   = 0

########################################################################
########################################################################
#####                                                              #####
#####           H E A D E R   S C A N N E R                        #####
#####                                                              #####
########################################################################
########################################################################


class HeaderScanner:
    """a class used to non-recursively detect which Linux kernel headers are
       used by a given set of input source files"""

    # to use the HeaderScanner, do the following:
    #
    #    scanner = HeaderScanner()
    #    for path in <your list of files>:
    #        scanner.parseFile(path)
    #
    #    # get the set of Linux headers included by your files
    #    headers = scanner.getHeaders()
    #
    #    # get the set of of input files that do include Linux headers
    #    files   = scanner.getFiles()
    #
    #    note that the result of getHeaders() is a set of strings, each one
    #    corresponding to a non-bracketed path name, e.g.:
    #
    #        set("linux/types","asm/types.h")
    #

    # the default algorithm is pretty smart and will analyze the input
    # files with a custom C pre-processor in order to optimize out macros,
    # get rid of comments, empty lines, etc..
    #
    # this avoids many annoying false positives... !!
    #

    # this regular expression is used to detect include paths that relate to
    # the kernel, by default, it selects one of:
    #    <linux/*>
    #    <asm/*>
    #    <asm-generic/*>
    #    <mtd/*>
    #
    re_combined =\
       re.compile(r"^.*<((%s)/[\d\w_\+\.\-/]*)>.*$" % string.join(kernel_dirs,"|") )
    # some kernel files choose to include files with relative paths (x86 32/64
    # dispatch for instance)
    re_rel_dir = re.compile(r'^.*"([\d\w_\+\.\-/]+)".*$')

    def __init__(self,config={}):
        """initialize a HeaderScanner"""
        self.reset()
        self.config = config

    def reset(self,config={}):
        self.files    = set()  # set of files being parsed for headers
        self.headers  = {}     # maps headers to set of users
        self.config   = config

    def checkInclude(self, line, from_file, kernel_root=None):
        relative = False
        m = HeaderScanner.re_combined.match(line)
        if kernel_root and not m:
            m = HeaderScanner.re_rel_dir.match(line)
            relative = True
        if not m: return

        header = m.group(1)
        if from_file:
            self.files.add(from_file)
            if kernel_root and relative:
                hdr_dir = os.path.realpath(os.path.dirname(from_file))
                hdr_dir = hdr_dir.replace("%s/" % os.path.realpath(kernel_root),
                                          "")
                if hdr_dir:
                    _prefix = "%s/" % hdr_dir
                else:
                    _prefix = ""
                header = "%s%s" % (_prefix, header)

        if not header in self.headers:
            self.headers[header] = set()

        if from_file:
            if verboseFind:
                print "=== %s uses %s" % (from_file, header)
            self.headers[header].add(from_file)

    def parseFile(self, path, arch=None, kernel_root=None):
        """parse a given file for Linux headers"""
        if not os.path.exists(path):
            return

        # since tokenizing the file is very slow, we first try a quick grep
        # to see if this returns any meaningful results. only if this is true
        # do we do the tokenization"""
        try:
            f = open(path, "rt")
        except:
            print "!!! can't read '%s'" % path
            return

        hasIncludes = False
        for line in f:
            if (HeaderScanner.re_combined.match(line) or
                (kernel_root and HeaderScanner.re_rel_dir.match(line))):
                hasIncludes = True
                break

        if not hasIncludes:
            if verboseSearch: print "::: " + path
            return

        if verboseSearch: print "*** " + path

        list = cpp.BlockParser().parseFile(path)
        if list:
            #list.removePrefixed("CONFIG_",self.config)
            macros = kernel_known_macros.copy()
            if kernel_root:
                macros.update(self.config)
                if arch and arch in kernel_default_arch_macros:
                    macros.update(kernel_default_arch_macros[arch])
            list.optimizeMacros(macros)
            list.optimizeIf01()
            includes = list.findIncludes()
            for inc in includes:
                self.checkInclude(inc, path, kernel_root)

    def getHeaders(self):
        """return the set of all needed kernel headers"""
        return set(self.headers.keys())

    def getHeaderUsers(self,header):
        """return the set of all users for a given header"""
        return set(self.headers.get(header))

    def getAllUsers(self):
        """return a dictionary mapping heaaders to their user set"""
        return self.headers.copy()

    def getFiles(self):
        """returns the set of files that do include kernel headers"""
        return self.files.copy()


##########################################################################
##########################################################################
#####                                                                #####
#####           H E A D E R   F I N D E R                            #####
#####                                                                #####
##########################################################################
##########################################################################


class KernelHeaderFinder:
    """a class used to scan the kernel headers themselves."""

    # this is different
    #  from a HeaderScanner because we need to translate the path returned by
    #  HeaderScanner.getHeaders() into possibly architecture-specific ones.
    #
    # for example, <asm/XXXX.h> needs to be translated in <asm-ARCH/XXXX.h>
    # where ARCH is appropriately chosen

    # here's how to use this:
    #
    #    scanner = HeaderScanner()
    #    for path in <your list of user sources>:
    #        scanner.parseFile(path)
    #
    #    used_headers = scanner.getHeaders()
    #    finder       = KernelHeaderFinder(used_headers, [ "arm", "x86" ],
    #                                      "<kernel_include_path>")
    #    all_headers  = finder.scanForAllArchs()
    #
    #   not that the result of scanForAllArchs() is a list of relative
    #   header paths that are not bracketed
    #

    def __init__(self,headers,archs,kernel_root,kernel_config):
        """init a KernelHeaderScanner,

            'headers' is a list or set of headers,
            'archs' is a list of architectures
            'kernel_root' is the path to the 'include' directory
             of your original kernel sources
        """

        if len(kernel_root) > 0 and kernel_root[-1] != "/":
            kernel_root += "/"
        #print "using kernel_root %s" % kernel_root
        self.archs         = archs
        self.searched      = set(headers)
        self.kernel_root   = kernel_root
        self.kernel_config = kernel_config
        self.needed        = {}
        self.setArch(arch=None)

    def setArch(self,arch=None):
        self.curr_arch = arch
        self.arch_headers = set()
        if arch:
            self.prefix = "asm-%s/" % arch
        else:
            self.prefix = None

    def pathFromHeader(self,header):
        path = header
        if self.prefix and path.startswith("asm/"):
            path = "%s%s" % (self.prefix, path[4:])
        return path

    def pathToHeader(self,path):
        if self.prefix and path.startswith(self.prefix):
            path = "asm/%s" % path[len(self.prefix):]
        return "%s" % path

    def setSearchedHeaders(self,headers):
        self.searched = set(headers)

    def scanForArch(self):
        fparser   = HeaderScanner(config=self.kernel_config)
        workqueue = []
        needed    = {}
        for h in self.searched:
            path = self.pathFromHeader(h)
            if not path in needed:
                needed[path] = set()
            workqueue.append(path)

        i = 0
        while i < len(workqueue):
            path = workqueue[i]
            i   += 1
            fparser.parseFile(self.kernel_root + path,
                              arch=self.curr_arch, kernel_root=self.kernel_root)
            for used in fparser.getHeaders():
                path  = self.pathFromHeader(used)
                if not path in needed:
                    needed[path] = set()
                    workqueue.append(path)
                for user in fparser.getHeaderUsers(used):
                    needed[path].add(user)

        # now copy the arch-specific headers into the global list
        for header in needed.keys():
            users = needed[header]
            if not header in self.needed:
                self.needed[header] = set()

            for user in users:
                self.needed[header].add(user)

    def scanForAllArchs(self):
        """scan for all architectures and return the set of all needed kernel headers"""
        for arch in self.archs:
            self.setArch(arch)
            self.scanForArch()

        return set(self.needed.keys())

    def getHeaderUsers(self,header):
        """return the set of all users for a given header"""
        return set(self.needed[header])

    def getArchHeaders(self,arch):
        """return the set of all <asm/...> headers required by a given architecture"""
        return set()  # XXX: TODO

#####################################################################################
#####################################################################################
#####                                                                           #####
#####           C O N F I G   P A R S E R                                       #####
#####                                                                           #####
#####################################################################################
#####################################################################################

class ConfigParser:
    """a class used to parse the Linux kernel .config file"""
    re_CONFIG_ = re.compile(r"^(CONFIG_\w+)=(.*)$")

    def __init__(self):
        self.items = {}
        self.duplicates = False

    def parseLine(self,line):
        line = string.strip(line)

        # skip empty and comment lines
        if len(line) == 0 or line[0] == "#":
            return

        m = ConfigParser.re_CONFIG_.match(line)
        if not m: return

        name  = m.group(1)
        value = m.group(2)

        if name in self.items:  # aarg, duplicate value
            self.duplicates = True

        self.items[name] = value

    def parseFile(self,path):
        f = file(path, "r")
        for line in f:
            if len(line) > 0:
                if line[-1] == "\n":
                    line = line[:-1]
                    if len(line) > 0 and line[-1] == "\r":
                        line = line[:-1]
                self.parseLine(line)
        f.close()

    def getDefinitions(self):
        """retrieve a dictionary containing definitions for CONFIG_XXX"""
        return self.items.copy()

    def __repr__(self):
        return repr(self.items)

    def __str__(self):
        return str(self.items)
