#define REDISMODULE_EXPERIMENTAL_API
#include "periodic.h"
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>

typedef struct RMUtilTimer {
  RMutilTimerFunc cb;
  RMUtilTimerTerminationFunc onTerm;
  void *privdata;
  struct timespec interval;
  pthread_t thread;
  pthread_mutex_t lock;
  pthread_cond_t cond;
} RMUtilTimer;

static struct timespec timespecAdd(struct timespec *a, struct timespec *b) {
  struct timespec ret;
  ret.tv_sec = a->tv_sec + b->tv_sec;

  long long ns = a->tv_nsec + b->tv_nsec;
  ret.tv_sec += ns / 1000000000;
  ret.tv_nsec = ns % 1000000000;
  return ret;
}

static void *rmutilTimer_Loop(void *ctx) {
  RMUtilTimer *tm = ctx;

  int rc = ETIMEDOUT;
  struct timespec ts;

  pthread_mutex_lock(&tm->lock);
  while (rc != 0) {
    clock_gettime(CLOCK_REALTIME, &ts);
    struct timespec timeout = timespecAdd(&ts, &tm->interval);
    if ((rc = pthread_cond_timedwait(&tm->cond, &tm->lock, &timeout)) == ETIMEDOUT) {

      // Create a thread safe context if we're running inside redis
      RedisModuleCtx *rctx = NULL;
      if (RedisModule_GetThreadSafeContext) rctx = RedisModule_GetThreadSafeContext(NULL);

      // call our callback...
      tm->cb(rctx, tm->privdata);

      // If needed - free the thread safe context.
      // It's up to the user to decide whether automemory is active there
      if (rctx) RedisModule_FreeThreadSafeContext(rctx);
    }
    if (rc == EINVAL) {
      perror("Error waiting for condition");
      break;
    }
  }

  // call the termination callback if needed
  if (tm->onTerm != NULL) {
    tm->onTerm(tm->privdata);
  }

  // free resources associated with the timer
  pthread_cond_destroy(&tm->cond);
  free(tm);

  return NULL;
}

/* set a new frequency for the timer. This will take effect AFTER the next trigger */
void RMUtilTimer_SetInterval(struct RMUtilTimer *t, struct timespec newInterval) {
  t->interval = newInterval;
}

RMUtilTimer *RMUtil_NewPeriodicTimer(RMutilTimerFunc cb, RMUtilTimerTerminationFunc onTerm,
                                     void *privdata, struct timespec interval) {
  RMUtilTimer *ret = malloc(sizeof(*ret));
  *ret = (RMUtilTimer){
      .privdata = privdata, .interval = interval, .cb = cb, .onTerm = onTerm,
  };
  pthread_cond_init(&ret->cond, NULL);
  pthread_mutex_init(&ret->lock, NULL);

  pthread_create(&ret->thread, NULL, rmutilTimer_Loop, ret);
  return ret;
}

int RMUtilTimer_Terminate(struct RMUtilTimer *t) {
  return pthread_cond_signal(&t->cond);
}
