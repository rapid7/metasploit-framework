//----utilities----//
#import "kernel_utils.h"
#import "patchfinder64.h"
#import "utils.h"
#import "offsets.h"
#import "offsetof.h"
#import "kexecute.h"
#import "vnode_utils.h"
#import "snapshot_utils.h"
#import "offsetof.h"
#import "offsets.h"
#import "amfi_utils.h"
#import "osobject.h"
#import "kernelSymbolFinder.h"
#import "cs_blob.h"

//---standard C stuff---//
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <unistd.h>
#import <spawn.h>
#import <sys/mman.h>
#import <sys/attr.h>

//---stuff---//
#import <mach/mach.h>
#import <sys/types.h>
#import <CommonCrypto/CommonDigest.h>

//---Obj-c stuff---//
#import <Foundation/Foundation.h>

extern uint32_t KASLR_Slide;
extern uint64_t KernelBase;
extern mach_port_t TFP0;

/*
 Purpose: Initialize jelbrekLib (first thing you have to call)
 Parameters:
    kernel task port (tfp0)
 Return values:
    1: tfp0 port not valid
    2: Something messed up while finding the kernel base
    3: patchfinder didn't initialize properly
    4: kernelSymbolFinder didn't initialize properly
 */
int init_jelbrek(mach_port_t tfpzero);
int init_with_kbase(mach_port_t tfpzero, uint64_t kernelBase); // iOS 12

/*
 Purpose: Free memory used by jelbrekLib & clean up (last thing you have to call)
*/
void term_jelbrek(void);

/*
 Purpose:
    Add a macho binary on the AMFI trustcache
 Parameters:
    A path to single macho or a directory for recursive patching
 Return values:
    -1: path doesn't exist
    -2: Couldn't find valid macho in directory
     2: Binary not an executable
     3: Binary bigger than 0x4000 bytes or something weird happened when running lstat
     4: Permission denied when trying to open file
     5: Something weird happened when reading data from the file
     6: Binary is not a macho
     7: file mmap() failed
*/
int trustbin(const char *path);

/*
 Purpose:
    Unsandboxes a process
 Parameters:
    The process ID
 Return values:
    pointer to original sandbox slot: successfully unsandboxed or already unsandboxed
    false: something went wrong
 */
uint64_t unsandbox(pid_t pid);

/*
 Purpose:
    Sandboxes a process
 Parameters:
    The process ID
    Kernel pointer to sandbox slot
 Return values:
    true: successfully sandboxed
    false: something went wrong
 */
BOOL sandbox(pid_t pid, uint64_t sb);

/*
 Purpose:
    Sets special codesigning flags on a process
 Parameters:
    The process ID
 Return values:
    true: successfully patched or already has flags
    false: something went wrong
 */
BOOL setcsflags(pid_t pid);

/*
 Purpose:
    Patches the UID & GID of a process to 0
 Parameters:
    The process ID
 Return values:
    true: successfully patched or already has root
    false: something went wrong
 */
BOOL rootify(pid_t pid);

/*
 Purpose:
    Sets TF_PLATFORM flag on a process & CS_PLATFORM_BINARY csflag
 Parameters:
    The process ID
 Return values:
    true: successfully patched or already has root
    false: something went wrong
 */
void platformize(pid_t pid);

/*
 Purpose:
    Adds a new entitlement on ones stored by AMFI (not the actual entitlements of csblob)
 Parameters:
    The process ID
    The entitlement (eg. com.apple.private.skip-library-validation)
    Entitlement value, either true or false
 Return values:
    true: successfully patched or already has entitlement
    false: something went wrong
 */
BOOL entitlePidOnAMFI(pid_t pid, const char *ent, BOOL val);

/*
 Purpose:
    Replaces entitlements stored on the csblob & ones on AMFI. Differently from above function this will FULLY REPLACE entitlements. Adding new ones on top is doable but for now this works.
 Parameters:
    The process ID
    The entitlement string (e.g. "<key>task_for_pid-allow</key><true/>")
 Return values:
    true: successfully patched
    false: something went wrong
 */
BOOL patchEntitlements(pid_t pid, const char *entitlementString);

/*
 Purpose:
    Borrows credentials from another process ID
 Parameters:
    The target's process ID
    The donor's process ID
 Return values:
    Original credentials (use to revert later)
 */
uint64_t borrowCredsFromPid(pid_t target, pid_t donor);

/*
 Purpose:
    Spawns a binary and borrows credentials from it
 Parameters:
    The target's process ID
    The donor binary path & up to 6 arguments (Leave NULL if not using)
 Return values:
    Success: Original credentials (use to revert later)
    Error: posix_spawn return value
 */
uint64_t borrowCredsFromDonor(pid_t target, char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

/*
 Purpose:
    Undoes crenetial dontaion
 Parameters:
    The target's process ID
    The original credentials
 */
void undoCredDonation(pid_t target, uint64_t origcred);

/*
 Purpose:
    Spawn a process as platform binary
 Parameters:
    Binary path
    Up to 6 arguments (Leave NULL if not using)
    environment variables (Leave NULL if not using)
 Return values:
    Success: child exit status
    Error: posix_spawn return value
 */
int launchAsPlatform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

/*
 Purpose:
    Spawn a process
 Parameters:
    Binary path
    Up to 6 arguments (Leave NULL if not using)
    environment variables (Leave NULL if not using)
 Return values:
    Success: child exit status
    Error: posix_spawn return value
 */
int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

/*
 Purpose:
    Spawn a process suspended
 Parameters:
    Binary path
    Up to 6 arguments (Leave NULL if not using)
    environment variables (Leave NULL if not using)
 Return values:
    Success: child pid
    Error: posix_spawn return value
 */
int launchSuspended(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env);

/*
 Purpose:
    Mount a device as read and write on a specified path
 Parameters:
    Device name
    Path to mount
 Return values:
    mount() return value
 */
int mountDevAtPathAsRW(const char* devpath, const char* path);

/*
 Purpose:
    Mount / as read and write on iOS 10.3-11.4b3
 Return values:
    0: mount succeeded
    -1: mount failed
 */
int remountRootFS(void);

/*
 Purpose:
    Get the kernel vnode pointer for a specified path
 Parameters:
    Target path
 Return values:
    Vnode pointer of path
 */
uint64_t getVnodeAtPath(const char *path);

/*
 Purpose:
    Patch host type to make hgsp() work
 Parameters:
    host port. mach_host_self() for the host port of this process
 Return value:
    YES: Success or already good
    NO: Failure
 
 WARNING:
    DO **NOT** USE WITH mach_host_self() ON A PROCESS THAT WAS MEANT TO RUN AS "mobile" (ANY app),
    ON A DEVICE WITH SENSTIVE INFORMATION OR IN A NON-DEVELOPER JAILBREAK
    THAT IN COMBINATION WITH setHSP4() WILL GIVE ANY APP THE ABILITY TO GET THE KERNEL TASK, FULL CONTROL OF YOUR DEVICE
 
    On a developer device, you can do that and will probably be very helpful for debugging :)
    The original idea was implemented by Ian Beer. Another example of this patch can be found inside FakeHostPriv() which creates a dummy port which acts like mach_host_self() of a root process
 */
BOOL PatchHostPriv(mach_port_t host);

/*
 Purpose:
    Do a hex dump I guess
 Parameters:
    Address in kernel from where to get data
    Size of data to get
 */
void HexDump(uint64_t addr, size_t size);

/*
 Purpose:
    Make a path invisible
 Parameters:
    path
 Return value:
    true: Success
    false: Failure
 */
BOOL hidePath(char *path);

/*
 Purpose:
    Allow mmap of executable from every process with read access to it
 Parameters:
    path
 Return value:
    true: Success
    false: Failure
 */
BOOL fixMmap(char *path);
