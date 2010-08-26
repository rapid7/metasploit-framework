# common python utility routines for the Bionic tool scripts

import sys, os, commands, string, commands

# basic debugging trace support
# call D_setlevel to set the verbosity level
# and D(), D2(), D3(), D4() to add traces
#
verbose = 0

def panic(msg):
    sys.stderr.write( find_program_name() + ": error: " )
    sys.stderr.write( msg )
    sys.exit(1)

def D(msg):
    global verbose
    if verbose > 0:
        print msg

def D2(msg):
    global verbose
    if verbose >= 2:
        print msg

def D3(msg):
    global verbose
    if verbose >= 3:
        print msg

def D4(msg):
    global verbose
    if verbose >= 4:
        print msg

def D_setlevel(level):
    global verbose
    verbose = level


#  other stuff
#
#
def find_program_name():
    return os.path.basename(sys.argv[0])

def find_program_dir():
    return os.path.dirname(sys.argv[0])

def find_file_from_upwards(from_path,target_file):
    """find a file in the current directory or its parents. if 'from_path' is None,
       seach from the current program's directory"""
    path = from_path
    if path == None:
        path = os.path.realpath(sys.argv[0])
        path = os.path.dirname(path)
        D("this script seems to be located in: %s" % path)

    while 1:
        D("probing "+path)
        if path == "":
            file = target_file
        else:
            file = path + "/" + target_file

        if os.path.isfile(file):
            D("found %s in %s" % (target_file, path))
            return file

        if path == "":
            return None

        path = os.path.dirname(path)

def find_bionic_root():
    file = find_file_from_upwards(None, "SYSCALLS.TXT")
    if file:
        return os.path.dirname(file)
    else:
        return None

def find_kernel_headers():
    """try to find the directory containing the kernel headers for this machine"""
    status, version = commands.getstatusoutput( "uname -r" )  # get Linux kernel version
    if status != 0:
        D("could not execute 'uname -r' command properly")
        return None

    # get rid of the "-xenU" suffix that is found in Xen virtual machines
    if len(version) > 5 and version[-5:] == "-xenU":
        version = version[:-5]

    path = "/usr/src/linux-headers-" + version
    D("probing %s for kernel headers" % (path+"/include"))
    ret = os.path.isdir( path )
    if ret:
        D("found kernel headers in: %s" % (path + "/include"))
        return path
    return None


# parser for the SYSCALLS.TXT file
#
class SysCallsTxtParser:
    def __init__(self):
        self.syscalls = []
        self.lineno   = 0

    def E(msg):
        print "%d: %s" % (self.lineno, msg)

    def parse_line(self, line):
        pos_lparen = line.find('(')
        E          = self.E
        if pos_lparen < 0:
            E("missing left parenthesis in '%s'" % line)
            return

        pos_rparen = line.rfind(')')
        if pos_rparen < 0 or pos_rparen <= pos_lparen:
            E("missing or misplaced right parenthesis in '%s'" % line)
            return

        return_type = line[:pos_lparen].strip().split()
        if len(return_type) < 2:
            E("missing return type in '%s'" % line)
            return

        syscall_func = return_type[-1]
        return_type  = string.join(return_type[:-1],' ')

        pos_colon = syscall_func.find(':')
        if pos_colon < 0:
            syscall_name = syscall_func
        else:
            if pos_colon == 0 or pos_colon+1 >= len(syscall_func):
                E("misplaced colon in '%s'" % line)
                return
            syscall_name = syscall_func[pos_colon+1:]
            syscall_func = syscall_func[:pos_colon]

        if pos_rparen > pos_lparen+1:
            syscall_params = line[pos_lparen+1:pos_rparen].split(',')
            params         = string.join(syscall_params,',')
        else:
            syscall_params = []
            params         = "void"

        number = line[pos_rparen+1:].strip()
        if number == "stub":
            syscall_id  = -1
            syscall_id2 = -1
        else:
            try:
                if number[0] == '#':
                    number = number[1:].strip()
                numbers = string.split(number,',')
                syscall_id  = int(numbers[0])
                syscall_id2 = syscall_id
                if len(numbers) > 1:
                    syscall_id2 = int(numbers[1])
            except:
                E("invalid syscall number in '%s'" % line)
                return

        t = { "id"     : syscall_id,
              "id2"    : syscall_id2,
              "name"   : syscall_name,
              "func"   : syscall_func,
              "params" : syscall_params,
              "decl"   : "%-15s  %s (%s);" % (return_type, syscall_func, params) }

        self.syscalls.append(t)

    def parse_file(self, file_path):
        fp = open(file_path)
        for line in fp.xreadlines():
            self.lineno += 1
            line = line.strip()
            if not line: continue
            if line[0] == '#': continue
            self.parse_line(line)

        fp.close()


class Output:
    def  __init__(self,out=sys.stdout):
        self.out = out

    def write(self,msg):
        self.out.write(msg)

    def writeln(self,msg):
        self.out.write(msg)
        self.out.write("\n")

class StringOutput:
    def __init__(self):
        self.line = ""

    def write(self,msg):
        self.line += msg
        D2("write '%s'" % msg)

    def writeln(self,msg):
        self.line += msg + '\n'
        D2("write '%s\\n'"% msg)

    def get(self):
        return self.line


def create_file_path(path):
    dirs = []
    while 1:
        parent = os.path.dirname(path)
        #print "parent: %s <- %s" % (parent, path)
        if parent == "/" or parent == "":
            break
        dirs.append(parent)
        path = parent

    dirs.reverse()
    for dir in dirs:
        #print "dir %s" % dir
        if os.path.isdir(dir):
            continue
        os.mkdir(dir)

def walk_source_files(paths,callback,args,excludes=[]):
    """recursively walk a list of paths and files, only keeping the source files in directories"""
    for path in paths:
        if not os.path.isdir(path):
            callback(path,args)
        else:
            for root, dirs, files in os.walk(path):
                #print "w-- %s (ex: %s)" % (repr((root,dirs)), repr(excludes))
                if len(excludes):
                    for d in dirs[:]:
                        if d in excludes:
                            dirs.remove(d)
                for f in files:
                    r, ext = os.path.splitext(f)
                    if ext in [ ".h", ".c", ".cpp", ".S" ]:
                        callback( "%s/%s" % (root,f), args )

def cleanup_dir(path):
    """create a directory if needed, and ensure that it is totally empty
       by removing any existing content in it"""
    if not os.path.exists(path):
        os.mkdir(path)
    else:
        for root, dirs, files in os.walk(path, topdown=False):
            if root.endswith("kernel_headers/"):
                # skip 'kernel_headers'
                continue
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))

def update_file( path, newdata ):
    """update a file on disk, only if its content has changed"""
    if os.path.exists( path ):
        try:
            f = open( path, "r" )
            olddata = f.read()
            f.close()
        except:
            D("update_file: cannot read existing file '%s'" % path)
            return 0

        if oldata == newdata:
            D2("update_file: no change to file '%s'" % path )
            return 0

        update = 1
    else:
        try:
            create_file_path(path)
        except:
            D("update_file: cannot create path to '%s'" % path)
            return 0

    f = open( path, "w" )
    f.write( newdata )
    f.close()

    return 1


class BatchFileUpdater:
    """a class used to edit several files at once"""
    def __init__(self):
        self.old_files = set()
        self.new_files = set()
        self.new_data  = {}

    def readFile(self,path):
        #path = os.path.realpath(path)
        if os.path.exists(path):
            self.old_files.add(path)

    def readDir(self,path):
        #path = os.path.realpath(path)
        for root, dirs, files in os.walk(path):
            for f in files:
                dst = "%s/%s" % (root,f)
                self.old_files.add(dst)

    def editFile(self,dst,data):
        """edit a destination file. if the file is not mapped from a source,
           it will be added. return 0 if the file content wasn't changed,
           1 if it was edited, or 2 if the file is new"""
        #dst = os.path.realpath(dst)
        result = 1
        if os.path.exists(dst):
            f = open(dst, "r")
            olddata = f.read()
            f.close()
            if olddata == data:
                self.old_files.remove(dst)
                return 0
        else:
            result = 2

        self.new_data[dst] = data
        self.new_files.add(dst)
        return result

    def getChanges(self):
        """determine changes, returns (adds, deletes, edits)"""
        adds    = set()
        edits   = set()
        deletes = set()

        for dst in self.new_files:
            if not (dst in self.old_files):
                adds.add(dst)
            else:
                edits.add(dst)

        for dst in self.old_files:
            if not dst in self.new_files:
                deletes.add(dst)

        return (adds, deletes, edits)

    def _writeFile(self,dst,data=None):
        if not os.path.exists(os.path.dirname(dst)):
            create_file_path(dst)
        if data == None:
            data = self.new_data[dst]
        f = open(dst, "w")
        f.write(self.new_data[dst])
        f.close()

    def updateFiles(self):
        adds, deletes, edits = self.getChanges()

        for dst in sorted(adds):
            self._writeFile(dst)

        for dst in sorted(edits):
            self._writeFile(dst)

        for dst in sorted(deletes):
            os.remove(dst)

    def updateP4Files(self):
        adds, deletes, edits = self.getChanges()

        if len(adds):
            files = string.join(sorted(adds)," ")
            D( "%d new files will be p4 add-ed" % len(adds) )
            for dst in adds:
                self._writeFile(dst)
            D2("P4 ADDS: %s" % files)
            o = commands.getoutput( "p4 add " + files )
            D2( o )

        if len(edits):
            files = string.join(sorted(edits)," ")
            D( "%d files will be p4 edit-ed" % len(edits) )
            D2("P4 EDITS: %s" % files)
            o = commands.getoutput( "p4 edit " + files )
            D2( o )
            for dst in edits:
                self._writeFile(dst)

        if len(deletes):
            files = string.join(sorted(deletes)," ")
            D( "%d files will be p4 delete-d" % len(deletes) )
            D2("P4 DELETES: %s" % files)
            o = commands.getoutput( "p4 delete " + files )
            D2( o )
