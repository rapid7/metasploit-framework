Welcome to Bionic, Android's small and custom C library for the Android
platform.

Bionic is mainly a port of the BSD C library to our Linux kernel with the
following additions/changes:

- no support for locales
- no support for wide chars (i.e. multi-byte characters)
- its own smallish implementation of pthreads based on Linux futexes
- support for x86, ARM and ARM thumb CPU instruction sets and kernel interfaces

Bionic is released under the standard 3-clause BSD License

Bionic doesn't want to implement all features of a traditional C library, we only
add features to it as we need them, and we try to keep things as simple and small
as possible. Our goal is not to support scaling to thousands of concurrent threads
on multi-processors machines; we're running this on cell-phones, damnit !!

Note that Bionic doesn't provide a libthread_db or a libm implementation.


Adding new syscalls:
====================

Bionic provides the gensyscalls.py Python script to automatically generate syscall
stubs from the list defined in the file SYSCALLS.TXT. You can thus add a new syscall
by doing the following:

- edit SYSCALLS.TXT
- add a new line describing your syscall, it should look like:

   return_type  syscall_name(parameters)    syscall_number

- in the event where you want to differentiate the syscall function from its entry name,
  use the alternate:

   return_type  funcname:syscall_name(parameters)  syscall_number

- additionally, if the syscall number is different between ARM and x86, use:

   return_type  funcname[:syscall_name](parameters)   arm_number,x86_number

- a syscall number can be -1 to indicate that the syscall is not implemented on
  a given platform, for example:

   void   __set_tls(void*)   arm_number,-1


the comments in SYSCALLS.TXT contain more information about the line format

You can also use the 'checksyscalls.py' script to check that all the syscall
numbers you entered are correct. It does so by looking at the values defined in
your Linux kernel headers. The script indicates where the values are incorrect
and what is expected instead.
