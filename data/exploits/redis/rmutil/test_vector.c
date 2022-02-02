#include "vector.h"
#include <stdio.h>
#include "test.h"

int testVector() {

  Vector *v = NewVector(int, 1);
  ASSERT(v != NULL);
  // Vector_Put(v, 0, 1);
  // Vector_Put(v, 1, 3);
  for (int i = 0; i < 10; i++) {
    Vector_Push(v, i);
  }
  ASSERT_EQUAL(10, Vector_Size(v));
  ASSERT_EQUAL(16, Vector_Cap(v));

  for (int i = 0; i < Vector_Size(v); i++) {
    int n;
    int rc = Vector_Get(v, i, &n);
    ASSERT_EQUAL(1, rc);
    // printf("%d %d\n", rc, n);

    ASSERT_EQUAL(n, i);
  }

  Vector_Free(v);

  v = NewVector(char *, 0);
  int N = 4;
  char *strings[4] = {"hello", "world", "foo", "bar"};

  for (int i = 0; i < N; i++) {
    Vector_Push(v, strings[i]);
  }
  ASSERT_EQUAL(N, Vector_Size(v));
  ASSERT(Vector_Cap(v) >= N);

  for (int i = 0; i < Vector_Size(v); i++) {
    char *x;
    int rc = Vector_Get(v, i, &x);
    ASSERT_EQUAL(1, rc);
    ASSERT_STRING_EQ(x, strings[i]);
  }

  int rc = Vector_Get(v, 100, NULL);
  ASSERT_EQUAL(0, rc);

  Vector_Free(v);

  return 0;
  // Vector_Push(v, "hello");
  // Vector_Push(v, "world");
  // char *x = NULL;
  // int rc = Vector_Getx(v, 0, &x);
  // printf("rc: %d got %s\n", rc, x);
}

TEST_MAIN({ TESTFUNC(testVector); });
