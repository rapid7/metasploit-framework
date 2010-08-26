#include <signal.h>

extern int __sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
extern void __sig_restorer();

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    struct sigaction real_act;

    /* If the caller has not set a custom restorer, then set up a default one.
     * The code will function properly without this, however GDB will not be
     * able to recognize the stack frame as a signal trampoline, because it
     * is hardcoded to look for the instruction sequence that glibc uses in
     * its custom restorer.  By creating our own restorer with the same
     * sequence, we ensure that GDB correctly identifies this as a signal
     * trampoline frame.
     *
     * See http://sourceware.org/ml/gdb/2010-01/msg00143.html for more
     * information on this.*/
    if(act && !(act->sa_flags & SA_RESTORER)) {
        real_act = *act;
        real_act.sa_flags |= SA_RESTORER;
        real_act.sa_restorer = __sig_restorer;

        act = &real_act;
    }

    return __sigaction(signum, act, oldact);
}
