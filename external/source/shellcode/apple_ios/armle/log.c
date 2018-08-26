#include <stdio.h>
#include <string.h>

#include <asl.h>

int main() {
  asl_log(0, 0, ASL_LEVEL_ERR, "hello from log!\n");
  return 0;
}

