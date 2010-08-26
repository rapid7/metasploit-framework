/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * this header is used to define signal constants and names;
 * it might be included several times
 */

#ifndef __BIONIC_SIGDEF
#error __BIONIC_SIGDEF not defined
#endif

__BIONIC_SIGDEF(HUP,1,"Hangup")
__BIONIC_SIGDEF(INT,2,"Interrupt")
__BIONIC_SIGDEF(QUIT,3,"Quit")
__BIONIC_SIGDEF(ILL,4,"Illegal instruction")
__BIONIC_SIGDEF(TRAP,5,"Trap")
__BIONIC_SIGDEF(ABRT,6,"Aborted")
__BIONIC_SIGDEF(BUS,7,"Bus error")
__BIONIC_SIGDEF(FPE,8,"Floating point exception")
__BIONIC_SIGDEF(KILL,9,"Killed")
__BIONIC_SIGDEF(USR1,10,"User signal 1")
__BIONIC_SIGDEF(SEGV,11,"Segmentation fault")
__BIONIC_SIGDEF(USR2,12,"User signal 2")
__BIONIC_SIGDEF(PIPE,13,"Broken pipe")
__BIONIC_SIGDEF(ALRM,14,"Alarm clock")
__BIONIC_SIGDEF(TERM,15,"Terminated")
__BIONIC_SIGDEF(STKFLT,16,"Stack fault")
__BIONIC_SIGDEF(CHLD,17,"Child exited")
__BIONIC_SIGDEF(CONT,18,"Continue")
__BIONIC_SIGDEF(STOP,19,"Stopped (signal)")
__BIONIC_SIGDEF(TSTP,20,"Stopped")
__BIONIC_SIGDEF(TTIN,21,"Stopped (tty input)")
__BIONIC_SIGDEF(TTOU,22,"Stopper (tty output)")
__BIONIC_SIGDEF(URG,23,"Urgent I/O condition")
__BIONIC_SIGDEF(XCPU,24,"CPU time limit exceeded")
__BIONIC_SIGDEF(XFSZ,25,"File size limit exceeded")
__BIONIC_SIGDEF(VTALRM,26,"Virtual timer expired")
__BIONIC_SIGDEF(PROF,27,"Profiling timer expired")
__BIONIC_SIGDEF(WINCH,28,"Window size changed")
__BIONIC_SIGDEF(IO,29,"I/O possible")
__BIONIC_SIGDEF(PWR,30,"Power failure")
__BIONIC_SIGDEF(SYS,31,"Bad system call")

#undef __BIONIC_SIGDEF
