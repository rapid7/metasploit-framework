#ifndef RMUTIL_PERIODIC_H_
#define RMUTIL_PERIODIC_H_
#include <time.h>
#include <redismodule.h>

/** periodic.h - Utility periodic timer running a task repeatedly every given time interval */

/* RMUtilTimer - opaque context for the timer */
struct RMUtilTimer;

/* RMutilTimerFunc - callback type for timer tasks. The ctx is a thread-safe redis module context
 * that should be locked/unlocked by the callback when running stuff against redis. privdata is
 * pre-existing private data */
typedef void (*RMutilTimerFunc)(RedisModuleCtx *ctx, void *privdata);

typedef void (*RMUtilTimerTerminationFunc)(void *privdata);

/* Create and start a new periodic timer. Each timer has its own thread and can only be run and
 * stopped once. The timer runs `cb` every `interval` with `privdata` passed to the callback. */
struct RMUtilTimer *RMUtil_NewPeriodicTimer(RMutilTimerFunc cb, RMUtilTimerTerminationFunc onTerm,
                                            void *privdata, struct timespec interval);

/* set a new frequency for the timer. This will take effect AFTER the next trigger */
void RMUtilTimer_SetInterval(struct RMUtilTimer *t, struct timespec newInterval);

/* Stop the timer loop, call the termination callbck to free up any resources linked to the timer,
 * and free the timer after stopping.
 *
 * This function doesn't wait for the thread to terminate, as it may cause a race condition if the
 * timer's callback is waiting for the redis global lock.
 * Instead you should make sure any resources are freed by the callback after the thread loop is
 * finished.
 *
 * The timer is freed automatically, so the callback doesn't need to do anything about it.
 * The callback gets the timer's associated privdata as its argument.
 *
 * If no callback is specified we do not free up privdata. If privdata is NULL we still call the
 * callback, as it may log stuff or free global resources.
 */
int RMUtilTimer_Terminate(struct RMUtilTimer *t);

/* DEPRECATED - do not use this function (well now you can't), use terminate instead
    Free the timer context. The caller should be responsible for freeing the private data at this
 * point */
// void RMUtilTimer_Free(struct RMUtilTimer *t);
#endif