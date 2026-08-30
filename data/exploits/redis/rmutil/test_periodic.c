#include <stdio.h>
#include <redismodule.h>
#include <unistd.h>
#include "periodic.h"
#include "assert.h"
#include "test.h"

void timerCb(RedisModuleCtx *ctx, void *p) {
  int *x = p;
  (*x)++;
}

int testPeriodic() {
  int x = 0;
  struct RMUtilTimer *tm = RMUtil_NewPeriodicTimer(
      timerCb, NULL, &x, (struct timespec){.tv_sec = 0, .tv_nsec = 10000000});

  sleep(1);

  ASSERT_EQUAL(0, RMUtilTimer_Terminate(tm));
  ASSERT(x > 0);
  ASSERT(x <= 100);
  return 0;
}

TEST_MAIN({ TESTFUNC(testPeriodic); });
